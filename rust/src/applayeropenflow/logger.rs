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

use std;
use crate::jsonbuilder::{JsonBuilder, JsonError};
use super::openflow::OPENFLOWTransaction;

fn log_openflow(tx: &OPENFLOWTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    if !tx.frames.is_empty() {
        js.set_string("request", "request")?;
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn rs_openflow_logger_log(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, OPENFLOWTransaction);
    log_openflow(tx, js).is_ok()
}
