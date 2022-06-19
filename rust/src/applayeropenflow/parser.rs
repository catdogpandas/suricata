/* Copyright (C) 2018 Open Information Security Foundation
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

use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use std;
use std::fmt;

use crate::smb::debug;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, FromPrimitive, Debug)]
pub enum OPENFLOWFrameType {
    PACKETIN = 10,
    UNHANDLED = 11,
}
impl fmt::Display for OPENFLOWFrameType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for OPENFLOWFrameType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let su = s.to_uppercase();
        let su_slice: &str = &*su;
        match su_slice {
            "PACKETIN" => Ok(OPENFLOWFrameType::PACKETIN),
            _ => Err(format!(
                "'{}' is not a valid value for OPENFLOWFrameType",
                s
            )),
        }
    }
}

pub struct OPENFLOWFrameHeader {
    pub version: u8,
    pub ftype: u8,
    pub flength: u16,
    pub transaction_id: u32,
}

fn parse_len(input: &str) -> Result<u32, std::num::ParseIntError> {
    input.parse::<u32>()
}

named!(pub openflow_parse_frame_header<OPENFLOWFrameHeader>,
do_parse!(
    version: be_u8 >>
    ftype: be_u8 >>
    flength: be_u16 >>
    transaction_id: be_u32 >>
    (OPENFLOWFrameHeader{version, ftype, flength,
        transaction_id})
));

#[derive(Debug)]
pub struct OPENFLOWFramePacketIn {
    pub buffer_id: u32,
    pub total_length: u16,
    pub reason: u8,
    pub table_id: u8,
    pub cookie: u64,
    pub match_type: u16,
    pub match_length: u16,
    pub match_data: Vec<u8>,
    pub pad: u16,
    pub data: Vec<u8>,
}
named!(pub openflow_parse_frame_packetin<OPENFLOWFramePacketIn>,
do_parse!(
    buffer_id: be_u32 >>
    total_length: be_u16 >>
    reason: be_u8 >>
    table_id: be_u8 >>
    cookie: be_u64 >>
    match_type:be_u16>>
    match_length:be_u16>>
    match_data:take!(match_length)>>
    pad:be_u16>>
    data:take!(total_length)>>
     (OPENFLOWFramePacketIn{buffer_id, total_length, reason,
        table_id,cookie,match_type,match_length,match_data:match_data.to_vec(),pad,data:data.to_vec()})
));

#[cfg(test)]
mod tests {

    use super::*;
    use nom::*;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {}
}
