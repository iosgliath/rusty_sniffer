// http://thomask.sdf.org/blog/2017/09/01/layer-2-raw-sockets-on-rustlinux.html
// https://www.oreilly.com/library/view/building-internet-firewalls/1565928717/ch04.html


extern crate libc;
extern crate mac_address;

use std::io;
use std::ptr;
use std::mem;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::convert::AsMut;
use std::net::Ipv6Addr;


use libc::{sockaddr_ll, sockaddr, recvfrom, c_void, socklen_t,socket, AF_PACKET, SOCK_RAW};

// https://elixir.bootlin.com/linux/v3.5/source/include/linux/if_ether.h#L47
const ETH_P_ALL: u16    = 0x0003;
const ETH_P_ARP: u16    = 0x0806;
const ETH_P_IP: u16     = 0x0800;
const ETH_P_IPV6: u16   = 0x86DD;

// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
const IP_P_ICMP: u8   = 0x01;
const IP_P_IGMP: u8    = 0x02;
const IP_P_TCP: u8    = 0x06;
const IP_P_UDP: u8    = 0x11;


type Mappings = HashMap<Ipv4Addr, MacAddr>;
type MacAddr = [u8; 6];

// #[repr(C)]
#[derive(Debug)]

struct RawEtherHdr {
    dst_mac:        [u8; 6],
    src_mac:        [u8; 6],
    ether_type:     [u8; 2],
}

struct Ether2Hdr {
    dst_mac:        mac_address::MacAddress,
    src_mac:        mac_address::MacAddress,
    ether_type:     u16,
}
impl Ether2Hdr {
    pub fn new_ether2_hdr(
        dst_mac: mac_address::MacAddress, src_mac: mac_address::MacAddress,
        ether_type: u16
    ) -> Self {
        Self {
            dst_mac, src_mac, ether_type
        }
    }
}

struct Ipv4Hdr {
    version:        u8,
    ihl:            u8,
    len:            u16,
    id:             u16,
    flag_reserved:  bool,
    flag_dontfrag:  bool,
    flag_morefrag:  bool,
    frag_offset:    u16,
    ttl:            u8,
    protocol:       u8,
    checksum:       u16,
    src_ip:         Ipv4Addr,
    dst_ip:         Ipv4Addr,
}
impl Ipv4Hdr {
    pub fn new_ipv4_hdr(
        version: u8, ihl: u8, len: u16, id: u16, flag_reserved: bool, flag_dontfrag: bool, flag_morefrag: bool,
        frag_offset: u16, ttl: u8, protocol: u8, checksum: u16, src_ip: Ipv4Addr, dst_ip: Ipv4Addr
    )  -> Self {
        Self {
            version, ihl, len, id, flag_reserved, flag_dontfrag, flag_morefrag,
            frag_offset, ttl, protocol, checksum, src_ip, dst_ip
        }
    }
}

struct Ipv6Hdr {
    version:        u8,
    traffic_class:  u8,
    flow_label:     u8,
    payload_len:    u16,
    next_header:    u8,
    hop_limit:      u8,
    src_ip:         Ipv6Addr,
    dst_ip:         Ipv6Addr,
}
impl Ipv6Hdr {
    pub fn new_ipv6_hdr(
        version: u8, traffic_class: u8, flow_label: u8, payload_len: u16, next_header:u8, hop_limit: u8,
        src_ip: Ipv6Addr, dst_ip: Ipv6Addr
    )  -> Self {
        Self {
            version, traffic_class, flow_label, payload_len, next_header, hop_limit,
            src_ip, dst_ip
        }
    }
}

struct ArpHdr {
    htype:  u16,
    ptype:  u16,
    hlen:   u8,
    plen:   u8,
    oper:   u16,
    sha:    mac_address::MacAddress,
    spa:    Ipv4Addr,
    tha:    mac_address::MacAddress,
    tpa:    Ipv4Addr
}
impl ArpHdr {
    pub fn new_arp_hdr(
        htype: u16, ptype: u16, hlen: u8, plen: u8, oper: u16, sha: mac_address::MacAddress,
        spa: Ipv4Addr, tha: mac_address::MacAddress, tpa: Ipv4Addr
    )  -> Self {
        Self {
            htype, ptype, hlen, plen, oper, sha,
            spa, tha, tpa
        }
    }
}

struct TcpHdr {
    src_port:   u16,
    dst_port:   u16,
    seqno:      u32,
    ackno:      u32,
    offset:     u8,
    ns:         bool,
    cwr:        bool,
    ece:        bool,
    urg:        bool,
    ack:        bool,
    psh:        bool,
    rst:        bool,
    syn:        bool,
    fin:        bool,
    window:     u16,
    checksum:   u16,
}

impl TcpHdr {
    pub fn new_tcp_hdr(
        src_port: u16, dst_port: u16, seqno: u32, ackno: u32, offset: u8, ns: bool, cwr: bool, ece: bool, urg: bool,
        ack: bool, psh: bool, rst: bool, syn: bool, fin: bool, window: u16, checksum: u16
    )  -> Self {
        Self {
            src_port, dst_port, seqno, ackno, offset, ns, cwr, ece, urg,
            ack, psh, rst, syn, fin, window, checksum
        }
    }
}

struct UdpHdr {
    src_port: u16,
    dst_port: u16,
    len: u16,
    checksum: u16,
}

impl UdpHdr {
    pub fn new_udp_hdr(
        src_port: u16, dst_port: u16, len:u16, checksum:u16
    )  -> Self {
        Self {
            src_port, dst_port, len, checksum
        }
    }
}

struct IcmpHdr {
    ptype: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    seqno: u16
}

impl IcmpHdr {
    pub fn new_icmp_hdr(
        ptype: u8, code: u8, checksum: u16, identifier: u16, seqno: u16
    )  -> Self {
        Self {
            ptype, code, checksum, identifier, seqno
        }
    }
}


enum Header {
    Ether2(Ether2Hdr),
    Ipv4(Ipv4Hdr),
    Ipv6(Ipv6Hdr),
    Arp(ArpHdr),
    Tcp(TcpHdr),
    Udp(UdpHdr),
    Icmp(IcmpHdr),
}

type EtherCallback = fn(fd: i32, mappings: &Mappings, sender: sockaddr_ll, packet: &[u8], ip_frame_method: &Vec<IpFrameMethod>, transport_frame_method: &Vec<TransportFrameMethod>)-> ();
struct EtherFrameMethod {
    name:   String,
    value:  u16,
    parser: EtherCallback
}
impl EtherFrameMethod {
    pub fn new_ether_frame_method(
        name: String, value: u16, parser: EtherCallback
    )  -> Self {
        Self {
            name, value, parser,
        }
    }
}

type IpCallback = fn(packet: &[u8])-> (Header, u8, u8);
struct IpFrameMethod {
    name:   String,
    value:  u16,
    parser: IpCallback
}
impl IpFrameMethod {
    pub fn new_ip_frame_method(
        name: String, value: u16, parser: IpCallback
    )  -> Self {
        Self {
            name, value, parser,
        }
    }
}

type TransportCallback = fn(packet: &[u8]);
struct TransportFrameMethod {
    name:   String,
    value:  u8,
    parser: TransportCallback
}
impl TransportFrameMethod {
    pub fn new_transport_frame_method(
        name: String, value: u8, parser: TransportCallback
    )  -> Self {
        Self {
            name, value, parser,
        }
    }
}


fn main() {

    let mut mappings: Mappings = HashMap::new();

    let (ether_frame_methods, ip_frame_methods, transport_frame_methods) = init_knowledge();

    let filtering_frame: Vec<&EtherFrameMethod> = ether_frame_methods
        .iter()
        .filter(|voc| voc.name == "ALL")
        .collect();
    println!("Filtering frame :\n{:?}", filtering_frame[0].name);

    match listen(&mappings, &filtering_frame[0].name, &filtering_frame[0].value, filtering_frame[0].parser, &ip_frame_methods, &transport_frame_methods) {
        Ok(_) => return,
        Err(e) => println!("Error: {}", e)
    }
}

/////////////////////////
/// UTILITIES
///////////////////////

fn listen(mappings:&Mappings, name: &str, value: &u16, parser: fn(fd: i32, mappings: &Mappings, sender: sockaddr_ll, packet: &[u8], ip_f_methods: &Vec<IpFrameMethod>, t_f_methods: &Vec<TransportFrameMethod>), ip_frame_methods: &Vec<IpFrameMethod>, transport_frame_methods: &Vec<TransportFrameMethod>)-> io::Result<()> {
    let mut sender_addr: sockaddr_ll = unsafe { mem::zeroed() };
    let mut packet_buf: [u8; 1024] = [0; 1024];

    println!("\nOpening socket for {} protocol(s)", name);
    let fd  = open_fd(value)?;

    println!("\nListening ...\n");
    loop {
        match recv_single_packet(fd, &mut sender_addr, &mut packet_buf) {
            Ok(len) => parser(fd, mappings, sender_addr, &packet_buf[0..len], ip_frame_methods, transport_frame_methods),
            Err(e) => return Err(e)
        }
    }
}

fn open_fd(protocol: &u16) -> io::Result<i32> {
    // Open a raw AF_PACKET socket for the chosen protocol.
    unsafe {
        match socket(AF_PACKET, SOCK_RAW, protocol.to_be() as i32) {
            -1 => Err(io::Error::last_os_error()),
            fd => Ok(fd)
        }
    }
}

fn recv_single_packet(fd: i32, addr: &mut sockaddr_ll, buf: &mut [u8]) -> io::Result<usize> {
    //
    // Wait for a single packet on the fd, reading it into a buffer. Also writes the sockaddr
    // into the structure provided as a mutable parameter.
    //
    let len: isize;
    let mut addr_buf_sz: socklen_t = mem::size_of::<sockaddr_ll>() as socklen_t;
    unsafe {
        let addr_ptr = mem::transmute::<*mut sockaddr_ll, *mut sockaddr>(addr);
        // https://man7.org/linux/man-pages/man2/recvfrom.2.html
        // https://man7.org/linux/man-pages/man2/read.2.html
            len = match recvfrom(fd, // file descriptor
                buf.as_mut_ptr() as *mut c_void,                    // pointer to buffer for frame content
                buf.len(),                                          // frame content buffer length
                0, // flags
                addr_ptr as *mut sockaddr,                          // pointer to buffer for sender address
                &mut addr_buf_sz) {                                 // sender address buffer length
                    -1 => {
                        return Err(io::Error::last_os_error());
                    },
            len => len
        };
    }
    // Return the number of valid bytes that were placed in the buffer
    Ok(len as usize)
}

fn init_knowledge()-> (Vec<EtherFrameMethod>, Vec<IpFrameMethod>, Vec<TransportFrameMethod>) {

    // /////////////////////////////
    // Initialise parsers
    // If you wish to add, Internet or Transport layer protocols:
    //      1. Create layer struc + impl (ex:ipv4_hr)
    //      1. create parsing function (ex:parse_ipv4_layer())
    //      2. add Name in tmp1 ("IPV4") // Value in tmp2 (0x0800) // parsing function name in tmp3 (parse_ipv4_layer)
    // Matching will then occur on its own, based on ether_type and protocol of Ethernet and Internet headers

    // Not usefull now, but base for custom packets analysis enabled
    //

    let tmp1 =      [String::from("ALL"), String::from("ARP"), String::from("IP"), String::from("IPV6")];
    let tmp2 =      [ETH_P_ALL, ETH_P_ARP, ETH_P_IP, ETH_P_IPV6];
    let tmp3 =      [parse_ethernet_layer, parse_ethernet_layer, parse_ethernet_layer, parse_ethernet_layer];

    let mut ether_frame_methods = Vec::new();
    for i in 0..tmp1.len() {
        ether_frame_methods.push(
            EtherFrameMethod::new_ether_frame_method(tmp1[i].to_owned(), tmp2[i].to_owned(), tmp3[i].to_owned())
        );
    };

    // /////////////////////////////
    // Internet layer database
    let tmp1 =      [String::from("ARP"), String::from("Ipv4"), String::from("Ipv6")];             // NAMES
    let tmp2 =      [ETH_P_ARP, ETH_P_IP, ETH_P_IPV6];                                             // VALUES
    let tmp3 =      [parse_arp_payload, parse_ipv4_payload, parse_ipv6_payload];                   // PARSING FUNCTION

    let mut ip_frame_methods = Vec::new();
    for i in 0..tmp1.len() {
        ip_frame_methods.push(
            IpFrameMethod::new_ip_frame_method(tmp1[i].to_owned(), tmp2[i].to_owned(), tmp3[i].to_owned())
        );
    }

    // /////////////////////////////
    // Transport layer database
    let tmp1 =      [String::from("ICMP"), String::from("IGMP"),String::from("TCP"), String::from("UDP")];
    let tmp2 =      [IP_P_ICMP, IP_P_IGMP, IP_P_TCP, IP_P_UDP];
    let tmp3 =      [parse_icmp_payload, parse_igmp_payload, parse_tcp_payload, parse_udp_payload];

    let mut transport_frame_methods = Vec::new();
    for i in 0..tmp1.len() {
        transport_frame_methods.push(
            TransportFrameMethod::new_transport_frame_method(tmp1[i].to_owned(), tmp2[i].to_owned(), tmp3[i].to_owned())
        );
    }

    (ether_frame_methods, ip_frame_methods, transport_frame_methods)
}

fn clone_into_array<A, T>(slice: &[T]) -> A
// https://stackoverflow.com/questions/25428920/how-to-get-a-slice-as-an-array-in-rust
where
    A: Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = A::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

/////////////////////////
/// ETHERNET LAYER
///////////////////////

fn parse_ethernet_layer(fd: i32, mappings: &Mappings, sender: sockaddr_ll, packet: &[u8], ip_frame_methods: &Vec<IpFrameMethod>, transport_frame_methods: &Vec<TransportFrameMethod>) {

    if packet.len() < mem::size_of::<RawEtherHdr>() {
        // Ignore frame that was too short
        return;
    }

    println!("\n----------------------");

    let ether_hdr: RawEtherHdr = unsafe { ptr::read(packet.as_ptr() as *const _) };
    let src_mac = mac_address::MacAddress::new(ether_hdr.src_mac);
    let dst_mac = mac_address::MacAddress::new(ether_hdr.dst_mac);

    // https://stackoverflow.com/questions/50243866/how-do-i-convert-two-u8-primitives-into-a-u16-primitive?noredirect=1&lq=1
    let number = u16::from_str_radix(&format!("{:02x}{:02x}", ether_hdr.ether_type[0], ether_hdr.ether_type[1]), 16).unwrap();

    if number >= 1536 {
        println!("  EthernetII ");
        println!("      MAC         : {:} -> {:}\n      ETHER_TYPE  : {:?}", dst_mac, src_mac, number);
        let ethernet_hdr = Ether2Hdr::new_ether2_hdr(
            dst_mac,
            src_mac,
            number,
        );
        parse_internet_layer(&ethernet_hdr, ip_frame_methods, transport_frame_methods, &packet[14..]);
        return;
    }
}

/////////////////////////
/// INTERNET LAYER
///////////////////////

fn parse_internet_layer(eth_hdr: &Ether2Hdr, ip_frame_methods: &Vec<IpFrameMethod>, transport_frame_methods: &Vec<TransportFrameMethod>, packet: &[u8]) {

    let parsed_ip: Vec<(Header, u8, u8)> = ip_frame_methods
        .iter()
        .filter(|x| x.value == eth_hdr.ether_type)
        .map(|x| (x.parser)(packet))
        .collect();

    if parsed_ip.len()> 0 {
        let (header, protocol, idx) = &parsed_ip[0];
        match header {
            Header::Ipv4(ref hdr) => {
                parse_transport_layer(&protocol, transport_frame_methods, &packet[idx.to_owned() as usize..]);

            },
            Header::Ipv6(ref hdr) => {
                parse_transport_layer(&protocol, transport_frame_methods, &packet[idx.to_owned() as usize..]);
            },
            _ => (),
        }
    }
}

fn parse_arp_payload(packet: &[u8])-> (Header<>, u8, u8) {

    let mut protocol = 0;

    let arp_hdr: Header = Header::Arp(ArpHdr::new_arp_hdr(
        u16::from_str_radix(&format!("{:02x}{:02x}", packet[0], packet[1]), 16).unwrap(),
        u16::from_str_radix(&format!("{:02x}{:02x}", packet[2], packet[3]), 16).unwrap(),
        packet[4],
        packet[5],
        u16::from_str_radix(&format!("{:02x}{:02x}", packet[6], packet[7]), 16).unwrap(),
        mac_address::MacAddress::new(clone_into_array(&packet[8..14])),
        Ipv4Addr::new(packet[14], packet[15], packet[16], packet[17]),
        mac_address::MacAddress::new(clone_into_array(&packet[18..24])),
        Ipv4Addr::new(packet[24], packet[25], packet[26], packet[27]),
    ));

    match arp_hdr {
        Header::Arp(ref hdr) => {
            println!("  Arp ");
            println!("      HTYPE         : {:}", hdr.htype);
            println!("      PTYPE         : {:}", hdr.ptype);
            println!("      HLEN          : {:}", hdr.hlen);
            println!("      PLEN          : {:}", hdr.plen);
            println!("      OPER          : {:}", hdr.oper);
            println!("      HA            : {} -> {}", hdr.sha, hdr.tha);
            println!("      PA            : {:?} -> {:?}", hdr.spa, hdr.tpa);
            protocol = hdr.plen;
        },
        _ => println!("Something else"),
    }

    (arp_hdr, protocol, 1)
}

fn parse_ipv4_payload(packet: &[u8])-> (Header<>, u8, u8) {

    let mut protocol = 0;

    let ihl = (packet[0] & 0x0f) * 4;

    let ipv4_hdr: Header = Header::Ipv4(Ipv4Hdr::new_ipv4_hdr(
        (packet[0] & 0xf0) >> 4,
        (packet[0] & 0x0f) * 4,
        u16::from_str_radix(&format!("{:02x}{:02x}", packet[2], packet[3]), 16).unwrap(),
        u16::from_str_radix(&format!("{:02x}{:02x}", packet[4], packet[5]), 16).unwrap(),
        (&packet[6] & (1 << 7)) > 0,
        (&packet[6] & (1 << 6)) > 0,
        (&packet[6] & (1 << 5)) > 0,
        u16::from_str_radix(&format!("{:02x}{:02x}", packet[6], packet[7]), 16).unwrap() & 0x7ff,
        packet[8],
        packet[9],
        checksum(&packet[0..ihl as usize]),
        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
    ));

    match ipv4_hdr {
        Header::Ipv4(ref hdr) => {
            println!("  Ipv4 ");
            println!("      IP          : {:} -> {:}", hdr.src_ip, hdr.dst_ip);
            println!("      PROTOCOL    : {:}", hdr.protocol);
            println!("      FLAGS       : [R {:}]  [DF {:}]  [MF {:}]", hdr.flag_reserved, hdr.flag_dontfrag, hdr.flag_morefrag);
            protocol = hdr.protocol;
        },
        _ => println!("Something else"),
    }

     (ipv4_hdr, protocol, 14+ihl)
}

fn parse_ipv6_payload(packet: &[u8])-> (Header<>, u8, u8) {

    let mut protocol = 0;

    let ipv6_hdr: Header = Header::Ipv6(Ipv6Hdr::new_ipv6_hdr(
        (packet[0] & 0xf0) >> 4,
        ((packet[0] & 0xf) << 4) | (packet[1] >> 4),
        packet[0] >> 4,                                                    // !!!!!!!!!!!   PLACEHOLDER
        u16::from_ne_bytes(clone_into_array(&packet[4..6])),
        packet[6],
        packet[7],
        Ipv6Addr::new(
            u16::from_ne_bytes(clone_into_array(&packet[8..10])),
            u16::from_ne_bytes(clone_into_array(&packet[10..12])),
            u16::from_ne_bytes(clone_into_array(&packet[12..14])),
            u16::from_ne_bytes(clone_into_array(&packet[14..16])),
            u16::from_ne_bytes(clone_into_array(&packet[16..18])),
            u16::from_ne_bytes(clone_into_array(&packet[18..20])),
            u16::from_ne_bytes(clone_into_array(&packet[20..22])),
            u16::from_ne_bytes(clone_into_array(&packet[22..24])),
        ),
        Ipv6Addr::new(
            u16::from_ne_bytes(clone_into_array(&packet[24..26])),
            u16::from_ne_bytes(clone_into_array(&packet[26..28])),
            u16::from_ne_bytes(clone_into_array(&packet[28..30])),
            u16::from_ne_bytes(clone_into_array(&packet[30..32])),
            u16::from_ne_bytes(clone_into_array(&packet[32..34])),
            u16::from_ne_bytes(clone_into_array(&packet[34..36])),
            u16::from_ne_bytes(clone_into_array(&packet[36..38])),
            u16::from_ne_bytes(clone_into_array(&packet[38..40])),
        ),
    ));

    match ipv6_hdr {
        Header::Ipv6(ref hdr) => {
            println!("  Ipv6 ");
            println!("      IP          : {:} -> {:}", hdr.src_ip, hdr.dst_ip);
            println!("      PROTOCOL    : {:}", hdr.next_header);
            protocol = hdr.next_header;
        },
        _ => println!("Something else"),
    }

     (ipv6_hdr, protocol, 14+40)
}

fn checksum(buffer: &[u8]) -> u16 {
    /// Calculate the checksum for an IPv4 packet.
    // https://docs.rs/packet/0.1.2/i686-pc-windows-msvc/src/packet/ip/v4/mod.rs.html#30-51
	use std::io::Cursor;
	use byteorder::{ReadBytesExt, BigEndian};

	let mut result = 0xffffu32;
	let mut buffer = Cursor::new(buffer);

	while let Ok(value) = buffer.read_u16::<BigEndian>() {
		// Skip checksum field.
		if buffer.position() == 12 {
			continue;
		}

		result += value as u32;

		if result > 0xffff {
			result -= 0xffff;
		}
	}

	!result as u16
}

/////////////////////////0x00
/// TRANSPORT LAYER
///////////////////////

fn parse_transport_layer(ip_protocol: &u8, tp_frame_methods: &Vec<TransportFrameMethod>, packet: &[u8]) {
    let parsed_tp: Vec<()> = tp_frame_methods
        .iter()
        .filter(|x| x.value == *ip_protocol)
        .map(|x| (x.parser)(packet))
        .collect();

    if parsed_tp.len() == 0 {
        println!("No parser found");
    }

}

fn parse_icmp_payload(buffer: &[u8]) {

    if buffer.len() < 8 {
        // Ignore frame that was too short
        return;
    }

    let icmp_hdr: Header = Header::Icmp(IcmpHdr::new_icmp_hdr(
        buffer[0],
        buffer[1],
        u16::from_ne_bytes(clone_into_array(&buffer[2..4])),
        u16::from_ne_bytes(clone_into_array(&buffer[4..6])),
        u16::from_ne_bytes(clone_into_array(&buffer[6..8])),
    ));

    match icmp_hdr {
        Header::Icmp(ref hdr) => {
            println!("  Icmp                              len -> {}", buffer.len());
            println!("      TYPE        : {:}", hdr.ptype);
            println!("      CODE        : {:}", hdr.code);
        },
        _ => (),
    }
}

fn parse_igmp_payload(buffer: &[u8]) {

    if buffer.len() < 8 {
        // Ignore frame that was too short
        return;
    }

}

fn parse_tcp_payload(buffer: &[u8]) {

    if buffer.len() < 18 {
        // Ignore frame that was too short
        return;
    }

    let tcp_hdr: Header = Header::Tcp(TcpHdr::new_tcp_hdr(
        u16::from_ne_bytes(clone_into_array(&buffer[0..2])),
        u16::from_ne_bytes(clone_into_array(&buffer[2..4])),
        u32::from_ne_bytes(clone_into_array(&buffer[4..8])),
        u32::from_ne_bytes(clone_into_array(&buffer[8..12])),
        (buffer[12] & 0xf0) >> 4,
        (buffer[12] & 1) > 0,
        (buffer[13] & (1 << 7)) > 0,
        (buffer[13] & (1 << 6)) > 0,
        (buffer[13] & (1 << 5)) > 0,
        (buffer[13] & (1 << 4)) > 0,
        (buffer[13] & (1 << 3)) > 0,
        (buffer[13] & (1 << 2)) > 0,
        (buffer[13] & (1 << 1)) > 0,
        (buffer[13] & 1) > 0,
        u16::from_ne_bytes(clone_into_array(&buffer[14..16])),
        u16::from_ne_bytes(clone_into_array(&buffer[16..18])),
    ));

    match tcp_hdr {
        Header::Tcp(ref hdr) => {
            println!("  Tcp                              len -> {}", buffer.len());
            println!("      PORT        : {:} -> {:}", hdr.src_port, hdr.dst_port);
            println!("      FLAGS       : [SYN {:}] [ACK {:}] [FIN {:}] [URG {:}]", hdr.syn, hdr.ack, hdr.fin, hdr.urg);
        },
        _ => (),
    }
}

fn parse_udp_payload(buffer: &[u8]) {

    if buffer.len() < 8 {
        // Ignore frame that was too short
        return;
    }

    let udp_hdr: Header = Header::Udp(UdpHdr::new_udp_hdr(
        u16::from_ne_bytes(clone_into_array(&buffer[0..2])),
        u16::from_ne_bytes(clone_into_array(&buffer[2..4])),
        u16::from_ne_bytes(clone_into_array(&buffer[4..6])),
        u16::from_ne_bytes(clone_into_array(&buffer[6..8])),
    ));

    match udp_hdr {
        Header::Udp(ref hdr) => {
            println!("  Udp                              len -> {}", buffer.len());
            println!("      PORT        : {:} -> {:}", hdr.src_port, hdr.dst_port);
        },
        _ => (),
    }
}
