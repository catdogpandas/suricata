use nom::number::streaming::{be_u16, be_u32, be_u64, be_u8};
use std;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Ethernet
#[derive(Debug)]
pub struct EthernetHdr {
    eth_dst: Vec<u8>,
    eth_src: Vec<u8>,
    eth_type: u16,
}
named!(
    ethernet_header_parse<EthernetHdr>,
    do_parse!(
        eth_dst: take!(6)
            >> eth_src: take!(6)
            >> eth_type: be_u16
            >> (EthernetHdr {
                eth_dst: eth_dst.to_vec(),
                eth_src: eth_src.to_vec(),
                eth_type
            })
    )
);

//IPV4
#[derive(Debug)]
pub struct IPV4Hdr {
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
    ipv4_header_parse<IPV4Hdr>,
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
            >> (IPV4Hdr {
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
pub struct ICMPV4Hdr {
    ftype: u8,
    fcode: u8,
    checksum: u16,
}
named!(
    icmpv4_header_parse<ICMPV4Hdr>,
    do_parse!(
        ftype: be_u8
            >> fcode: be_u8
            >> checksum: be_u16
            >> (ICMPV4Hdr {
                ftype,
                fcode,
                checksum
            })
    )
);

#[derive(Debug)]
pub struct TCPHdr {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    offx2: u8,
    flags: u8,
}
named!(
    tcp_header_parse<TCPHdr>,
    do_parse!(
        sport: be_u16
            >> dport: be_u16
            >> seq: be_u32
            >> ack: be_u32
            >> offx2: be_u8
            >> flags: be_u8
            >> (TCPHdr {
                sport,
                dport,
                seq,
                ack,
                offx2,
                flags
            })
    )
);

#[derive(Debug)]
pub struct UDPHdr {
    sport: u16,
    dport: u16,
    len: u16,
    checksum: u16,
}
named!(
    udp_header_parse<UDPHdr>,
    do_parse!(
        sport: be_u16
            >> dport: be_u16
            >> len: be_u16
            >> checksum: be_u16
            >> (UDPHdr {
                sport,
                dport,
                len,
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
                            0x06 => match tcp_header_parse(rem) {
                                Ok((rem, tcp_header)) => {
                                    SCLogNotice!("{:?}", tcp_header);
                                }
                                Err(_) => {
                                    SCLogNotice!(
                                        "Transmission Control Protocol Header Parse Error"
                                    );
                                }
                            }, //tcp
                            0x07 => match udp_header_parse(rem) {
                                Ok((rem, udp_header)) => {
                                    SCLogNotice!("{:?}", udp_header);
                                }
                                Err(_) => {
                                    SCLogNotice!(
                                        "User Datagram Protocol Header Parse Error"
                                    );
                                }
                            }, //udp
                            _ => {}
                        }
                    }
                    Err(_) => {
                        SCLogNotice!("Internet Protocol Header Parse Error");
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
