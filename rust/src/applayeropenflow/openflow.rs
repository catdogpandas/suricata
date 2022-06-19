/* Copyright (C) 2018-2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

use super::parser::{self, OPENFLOWFramePacketIn};
use crate::applayer::{self, *};
use crate::core::{self, AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_TCP};
use nom;
use std;
use std::ffi::CString;
use std::io;
use std::mem::transmute;

static mut ALPROTO_OPENFLOW: AppProto = ALPROTO_UNKNOWN;

pub enum OPENFLOWFrameTypeData {
    PACKETIN(parser::OPENFLOWFramePacketIn),
    UNHANDLED,
}

pub struct OPENFLOWFrame {
    pub header: parser::OPENFLOWFrameHeader,
    pub data: OPENFLOWFrameTypeData,
}
pub struct OPENFLOWTransaction {
    tx_id: u64,
    pub frames: Vec<OPENFLOWFrame>,
    pub request: Option<String>,
    pub response: Option<String>,

    de_state: Option<*mut core::DetectEngineState>,
    events: *mut core::AppLayerDecoderEvents,
    tx_data: AppLayerTxData,
}

impl OPENFLOWTransaction {
    pub fn new() -> OPENFLOWTransaction {
        OPENFLOWTransaction {
            tx_id: 0,
            frames: Vec::new(),
            request: None,
            response: None,
            de_state: None,
            events: std::ptr::null_mut(),
            tx_data: AppLayerTxData::new(),
        }
    }

    pub fn free(&mut self) {
        if self.events != std::ptr::null_mut() {
            core::sc_app_layer_decoder_events_free_events(&mut self.events);
        }
        if let Some(state) = self.de_state {
            core::sc_detect_engine_state_free(state);
        }
    }
}

impl Drop for OPENFLOWTransaction {
    fn drop(&mut self) {
        self.free();
    }
}

pub struct OPENFLOWState {
    tx_id: u64,
    transactions: Vec<OPENFLOWTransaction>,
}

impl OPENFLOWState {
    pub fn new() -> Self {
        Self {
            tx_id: 0,
            transactions: Vec::new(),
        }
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&OPENFLOWTransaction> {
        for tx in &mut self.transactions {
            if tx.tx_id == tx_id + 1 {
                return Some(tx);
            }
        }
        return None;
    }

    fn new_tx(&mut self) -> OPENFLOWTransaction {
        let mut tx = OPENFLOWTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn parse_frame_data(&mut self, ftype: u8, input: &[u8]) -> OPENFLOWFrameTypeData {
        match num::FromPrimitive::from_u8(ftype) {
            Some(parser::OPENFLOWFrameType::PACKETIN) => {
                if input.len() < 32 {
                    return OPENFLOWFrameTypeData::UNHANDLED;
                }
                match parser::openflow_parse_frame_packetin(input) {
                    Ok((_, packetin)) => {
                        return OPENFLOWFrameTypeData::PACKETIN(packetin);
                    }
                    Err(_) => {
                        return OPENFLOWFrameTypeData::UNHANDLED;
                    }
                }
            }
            _ => {
                return OPENFLOWFrameTypeData::UNHANDLED;
            }
        }
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.len() == 0 {
            return AppLayerResult::ok();
        }

        SCLogNotice!("hash1");
        let mut start = input;
        while start.len() > 0 {
            match parser::openflow_parse_frame_header(start) {
                Ok((rem, head)) => {
                    start = rem;
                    if head.ftype == 0xa {
                        SCLogNotice!(
                            "OPENFLOWFrameHeader: {} {} {} {}",
                            head.version,
                            head.ftype,
                            head.flength,
                            head.transaction_id
                        );
                    }
                    // for packet_in data
                    if head.ftype != 0xa || head.flength <= 8 {
                        continue;
                    }
                    let hlsafe = if rem.len() <= (head.flength - 8) as usize {
                        rem.len()
                    } else {
                        head.flength as usize - 8
                    };
                    let txdata = self.parse_frame_data(head.ftype, &rem[..hlsafe]);
                    SCLogNotice!("OPENFLOWFramePacketIn: {:#?}", rem);

                    let mut tx = self.new_tx();
                    tx.frames.push(OPENFLOWFrame {
                        header: head,
                        data: txdata,
                    });
                    self.transactions.push(tx);
                }
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn tx_iterator(
        &mut self, min_tx_id: u64, state: &mut u64,
    ) -> Option<(&OPENFLOWTransaction, u64, bool)> {
        let mut index = *state as usize;
        let len = self.transactions.len();

        while index < len {
            let tx = &self.transactions[index];
            if tx.tx_id < min_tx_id + 1 {
                index += 1;
                continue;
            }
            *state = index as u64;
            return Some((tx, tx.tx_id - 1, (len - index) > 1));
        }

        return None;
    }
}

// C exports.

export_tx_get_detect_state!(rs_openflow_tx_get_detect_state, OPENFLOWTransaction);
export_tx_set_detect_state!(rs_openflow_tx_set_detect_state, OPENFLOWTransaction);

/// C entry point for a probing parser.
#[no_mangle]
pub extern "C" fn rs_openflow_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 2 bytes.
    SCLogNotice!("hash5");
    if input_len >= 8 && input != std::ptr::null_mut() {
        SCLogNotice!("- Request: {:?}", input);
        let slice = build_slice!(input, input_len as usize);
        SCLogNotice!("hash6");
        let openflow_version = slice[0];
        // version from 1 to 7
        if openflow_version <= 7 {
            return unsafe { ALPROTO_OPENFLOW };
        }
    }
    SCLogNotice!("hash7");
    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = OPENFLOWState::new();
    let boxed = Box::new(state);
    return unsafe { transmute(boxed) };
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_free(state: *mut std::os::raw::c_void) {
    // Just unbox...
    let _drop: Box<OPENFLOWState> = unsafe { transmute(state) };
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state = cast_pointer!(state, OPENFLOWState);
    state.free_tx(tx_id);
}

#[no_mangle]
pub extern "C" fn rs_openflow_parse_request(
    _flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    input: *const u8, input_len: u32, _data: *const std::os::raw::c_void, _flags: u8,
) -> AppLayerResult {
    let state = cast_pointer!(state, OPENFLOWState);

    SCLogNotice!("hash3");
    if input == std::ptr::null_mut() && input_len > 0 {
        AppLayerResult::ok()
    } else {
        let buf = build_slice!(input, input_len as usize);
        state.parse_request(buf)
    }
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state = cast_pointer!(state, OPENFLOWState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return unsafe { transmute(tx) };
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state = cast_pointer!(state, OPENFLOWState);
    return state.tx_id;
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_progress_completion_status(
    _direction: u8,
) -> std::os::raw::c_int {
    // This parser uses 1 to signal transaction completion status.
    return 1;
}

#[no_mangle]
pub extern "C" fn rs_openflow_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, OPENFLOWTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_get_events(
    tx: *mut std::os::raw::c_void,
) -> *mut core::AppLayerDecoderEvents {
    let tx = cast_pointer!(tx, OPENFLOWTransaction);
    return tx.events;
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_get_event_info(
    _event_name: *const std::os::raw::c_char, _event_id: *mut std::os::raw::c_int,
    _event_type: *mut core::AppLayerEventType,
) -> std::os::raw::c_int {
    return -1;
}

#[no_mangle]
pub extern "C" fn rs_openflow_state_get_event_info_by_id(
    _event_id: std::os::raw::c_int, _event_name: *mut *const std::os::raw::c_char,
    _event_type: *mut core::AppLayerEventType,
) -> i8 {
    return -1;
}
#[no_mangle]
pub extern "C" fn rs_openflow_state_get_tx_iterator(
    _ipproto: u8, _alproto: AppProto, state: *mut std::os::raw::c_void, min_tx_id: u64,
    _max_tx_id: u64, istate: &mut u64,
) -> applayer::AppLayerGetTxIterTuple {
    let state = cast_pointer!(state, OPENFLOWState);
    match state.tx_iterator(min_tx_id, istate) {
        Some((tx, out_tx_id, has_next)) => {
            let c_tx = unsafe { transmute(tx) };
            let ires = applayer::AppLayerGetTxIterTuple::with_values(c_tx, out_tx_id, has_next);
            return ires;
        }
        None => {
            return applayer::AppLayerGetTxIterTuple::not_found();
        }
    }
}

/// Get the request buffer for a transaction from C.
///
/// No required for parsing, but an example function for retrieving a
/// pointer to the request buffer from C for detection.
#[no_mangle]
pub extern "C" fn rs_openflow_get_request_buffer(
    tx: *mut std::os::raw::c_void, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, OPENFLOWTransaction);
    if let Some(ref request) = tx.request {
        if request.len() > 0 {
            unsafe {
                *len = request.len() as u32;
                *buf = request.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

/// Get the response buffer for a transaction from C.
#[no_mangle]
pub extern "C" fn rs_openflow_get_response_buffer(
    tx: *mut std::os::raw::c_void, buf: *mut *const u8, len: *mut u32,
) -> u8 {
    let tx = cast_pointer!(tx, OPENFLOWTransaction);
    if let Some(ref response) = tx.response {
        if response.len() > 0 {
            unsafe {
                *len = response.len() as u32;
                *buf = response.as_ptr();
            }
            return 1;
        }
    }
    return 0;
}

export_tx_data_get!(rs_openflow_get_tx_data, OPENFLOWTransaction);

// Parser name as a C style string.
const PARSER_NAME: &'static [u8] = b"openflow\0";

#[no_mangle]
pub unsafe extern "C" fn rs_openflow_register_parser() {
    let default_port = CString::new("[6633]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_openflow_probing_parser),
        probe_tc: Some(rs_openflow_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_openflow_state_new,
        state_free: rs_openflow_state_free,
        tx_free: rs_openflow_state_tx_free,
        parse_ts: rs_openflow_parse_request,
        parse_tc: rs_openflow_parse_request,
        get_tx_count: rs_openflow_state_get_tx_count,
        get_tx: rs_openflow_state_get_tx,
        tx_get_comp_st: rs_openflow_state_progress_completion_status,
        tx_get_progress: rs_openflow_tx_get_alstate_progress,
        get_de_state: rs_openflow_tx_get_detect_state,
        set_de_state: rs_openflow_tx_set_detect_state,
        get_events: Some(rs_openflow_state_get_events),
        get_eventinfo: Some(rs_openflow_state_get_event_info),
        get_eventinfo_byid: Some(rs_openflow_state_get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_files: None,
        get_tx_iterator: Some(rs_openflow_state_get_tx_iterator),
        get_tx_data: rs_openflow_get_tx_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_OPENFLOW = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust openflow parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for OPENFLOW.");
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_probe() {
        // assert!(probe(b"1").is_err());
        // assert!(probe(b"1:").is_ok());
        // assert!(probe(b"123456789:").is_ok());
        // assert!(probe(b"0123456789:").is_err());
    }

    #[test]
    fn test_incomplete() {
        let mut state = OPENFLOWState::new();
        let buf = b"5:Hello3:bye";

        let r = state.parse_request(&buf[0..0]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        let r = state.parse_request(&buf[0..1]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 2
            }
        );

        let r = state.parse_request(&buf[0..2]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 0,
                needed: 3
            }
        );

        // This is the first message and only the first message.
        let r = state.parse_request(&buf[0..7]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 0,
                consumed: 0,
                needed: 0
            }
        );

        // The first message and a portion of the second.
        let r = state.parse_request(&buf[0..9]);
        assert_eq!(
            r,
            AppLayerResult {
                status: 1,
                consumed: 7,
                needed: 3
            }
        );
    }
}
