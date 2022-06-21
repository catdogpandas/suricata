use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use std;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Ethernet
#[derive(Debug)]
pub struct EthernetHdr_ {
    eth_dst: Vec<u8>,
    eth_src: Vec<u8>,
    eth_type: u16,
}
named!(
    ethernet_header_parse<EthernetHdr_>,
    do_parse!(
        eth_dst: take!(8)
            >> eth_src: take!(8)
            >> eth_type: be_u16
            >> (EthernetHdr_ {
                eth_dst: eth_dst.to_vec(),
                eth_src: eth_src.to_vec(),
                eth_type
            })
    )
);

//IPV4
#[derive(Debug)]
pub struct IPV4Hdr_ {
    ip_verhl: u8, //**< version & header length */
    ip_tos: u8,   //**< type of service */
    ip_len: u16,  //**< length */
    ip_id: u16,   //**< id */
    ip_off: u16,  //**< frag offset */
    ip_ttl: u8,   //**< time to live */
    ip_proto: u8, //**< protocol (tcp, udp, etc) */
    ip_csum: u16, //**< checksum */

    ip_src: Ipv4Addr, //**< source address */
    ip_dst: Ipv4Addr, //**< destination address */
}
named!(
    ipv4_header_parse<IPV4Hdr_>,
    do_parse!(
        ip_verhl: be_u8
            >> ip_tos: be_u8
            >> ip_len: be_u16
            >> ip_id: be_u16
            >> ip_off: be_u16
            >> ip_ttl: be_u8
            >> ip_proto: be_u8
            >> ip_csum: be_u16
            >> ip_src: take!(4)
            >> ip_dst: take!(4)
            >> (IPV4Hdr_ {
                ip_verhl,
                ip_tos,
                ip_len,
                ip_id,
                ip_off,
                ip_ttl,
                ip_proto,
                ip_csum,
                ip_src: Ipv4Addr::new(ip_src[0], ip_src[1], ip_src[2], ip_src[3]),
                ip_dst: Ipv4Addr::new(ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3])
            })
    )
);

//ICMPV4
#[derive(Debug)]
pub struct ICMPV4Hdr_ {
    ftype: u8,
    fcode: u8,
    checksum: u16,
}
named!(
    icmpv4_header_parse<ICMPV4Hdr_>,
    do_parse!(
        ftype: be_u8
            >> fcode: be_u8
            >> checksum: be_u16
            >> (ICMPV4Hdr_ {
                ftype,
                fcode,
                checksum
            })
    )
);

pub fn openflow_data_packet_parse(input: &[u8]) {
    match ethernet_header_parse(input) {
        Ok((rem, ethernet_header)) => {
            SCLogNotice!("{:?}", ethernet_header);
            match ethernet_header.eth_type {
                0x0806 => {} //ARP
                0x0800 => match ipv4_header_parse(rem) {
                    Ok((rem, ipv4_header)) => {
                        SCLogNotice!("{:?}", ipv4_header);
                        match ipv4_header.ip_proto {
                            0x01 => match icmpv4_header_parse(rem) {
                                Ok((rem, icmpv4_header)) => {
                                    SCLogNotice!("{:?}", icmpv4_header);
                                }
                                Err(_) => {
                                    SCLogNotice!(
                                        "Internet Control Message Protocol Header Parse Error"
                                    );
                                }
                            }, //icmpv4
                            0x06 => {} //tcp
                            0x07 => {} //udp
                            _ => {}
                        }
                    }
                    Err(_) => {
                        SCLogNotice!("Internet Protocol Parse Error");
                    }
                }, //IPv4
                _ => {}
            }
        }
        Err(_) => {
            SCLogNotice!("Ethernet Header Parse Error");
        }
    }
}
