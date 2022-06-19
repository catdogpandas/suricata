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
use nom::number::streaming::{be_u16, be_u32, be_u8};

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
pub struct OPENFLOWFrameData {
    pub version: u8,
    pub ftype: u8,
    pub flength: u16,
    pub transaction_id: u32,
}

#[cfg(test)]
mod tests {

    use super::*;
    use nom::*;

    /// Simple test of some valid data.
    #[test]
    fn test_parse_valid() {
        
    }
}
