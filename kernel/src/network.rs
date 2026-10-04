use core::ptr::{addr_of, addr_of_mut, read_volatile};

use crate::arch;
use crate::io;
use crate::memory::PageTables;

const RTL_VENDOR: u16 = 0x10ec;
const RTL_DEVICE: u16 = 0x8139;
const RX_BYTES: usize = 8192;
const RX_STORAGE_BYTES: usize = RX_BYTES + 16 + 1536;
const TX_SLOTS: usize = 4;
const FRAME_BYTES: usize = 1536;
const DHCP_XID: u32 = 0x4f52_5956;
const DNS_PORT: u16 = 49_152;
const DNS_ID: u16 = 0x4f52;
const SSH_PORT: u16 = 22;
const TCP_RX_BYTES: usize = 16 * 1024;
const TCP_MSS: usize = 1200;

const REG_TSD0: u16 = 0x10;
const REG_TSAD0: u16 = 0x20;
const REG_RBSTART: u16 = 0x30;
const REG_COMMAND: u16 = 0x37;
const REG_CAPR: u16 = 0x38;
const REG_IMR: u16 = 0x3c;
const REG_ISR: u16 = 0x3e;
const REG_RCR: u16 = 0x44;
const REG_CONFIG1: u16 = 0x52;
const REG_MEDIA_STATUS: u16 = 0x58;

#[repr(align(4096))]
struct RxStorage([u8; RX_STORAGE_BYTES]);

#[repr(align(16))]
struct TxStorage([[u8; FRAME_BYTES]; TX_SLOTS]);

static mut RX_STORAGE: RxStorage = RxStorage([0; RX_STORAGE_BYTES]);
static mut TX_STORAGE: TxStorage = TxStorage([[0; FRAME_BYTES]; TX_SLOTS]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DhcpState {
    Disabled,
    Discovering,
    Requesting,
    Bound,
    TimedOut,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TcpState {
    Listen,
    SynReceived,
    Established,
    LastAck,
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub device: bool,
    pub link: bool,
    pub pci_bus: u8,
    pub pci_device: u8,
    pub io_base: u16,
    pub mac: [u8; 6],
    pub dhcp: DhcpState,
    pub ipv4: [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub dhcp_server: [u8; 4],
    pub lease_seconds: u32,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub arp_requests: u64,
    pub arp_replies: u64,
    pub arp_queries: u64,
    pub arp_responses: u64,
    pub icmp_requests: u64,
    pub icmp_replies: u64,
    pub ping_replies: u64,
    pub ping_rtt_ticks: u64,
    pub dns_queries: u64,
    pub dns_replies: u64,
    pub dropped: u64,
}

const EMPTY_SNAPSHOT: Snapshot = Snapshot {
    device: false,
    link: false,
    pci_bus: 0,
    pci_device: 0,
    io_base: 0,
    mac: [0; 6],
    dhcp: DhcpState::Disabled,
    ipv4: [0; 4],
    netmask: [0; 4],
    gateway: [0; 4],
    dns: [0; 4],
    dhcp_server: [0; 4],
    lease_seconds: 0,
    rx_packets: 0,
    tx_packets: 0,
    rx_bytes: 0,
    tx_bytes: 0,
    arp_requests: 0,
    arp_replies: 0,
    arp_queries: 0,
    arp_responses: 0,
    icmp_requests: 0,
    icmp_replies: 0,
    ping_replies: 0,
    ping_rtt_ticks: 0,
    dns_queries: 0,
    dns_replies: 0,
    dropped: 0,
};

struct Driver {
    state: Snapshot,
    rx_offset: usize,
    tx_slot: usize,
    tx_phys: [u32; TX_SLOTS],
    offered_ip: [u8; 4],
    neighbor_ip: [u8; 4],
    neighbor_mac: [u8; 6],
    ping_sequence: u16,
    dns_pending: bool,
    dns_answer: [u8; 4],
    tcp_state: TcpState,
    tcp_remote_mac: [u8; 6],
    tcp_remote_ip: [u8; 4],
    tcp_remote_port: u16,
    tcp_send_next: u32,
    tcp_send_una: u32,
    tcp_recv_next: u32,
    tcp_rx: [u8; TCP_RX_BYTES],
    tcp_rx_len: usize,
}

static mut DRIVER: Driver = Driver {
    state: EMPTY_SNAPSHOT,
    rx_offset: 0,
    tx_slot: 0,
    tx_phys: [0; TX_SLOTS],
    offered_ip: [0; 4],
    neighbor_ip: [0; 4],
    neighbor_mac: [0; 6],
    ping_sequence: 0,
    dns_pending: false,
    dns_answer: [0; 4],
    tcp_state: TcpState::Listen,
    tcp_remote_mac: [0; 6],
    tcp_remote_ip: [0; 4],
    tcp_remote_port: 0,
    tcp_send_next: 0,
    tcp_send_una: 0,
    tcp_recv_next: 0,
    tcp_rx: [0; TCP_RX_BYTES],
    tcp_rx_len: 0,
};

pub struct PingResult {
    pub address: [u8; 4],
    pub milliseconds: u64,
}

pub enum PingError {
    NetworkUnavailable,
    InvalidName,
    DnsTimeout,
    NeighborTimeout,
    EchoTimeout,
}

pub fn initialize(page_tables: &PageTables) -> bool {
    let Some((bus, device, io_base)) = find_rtl8139() else {
        return false;
    };

    let rx_va = unsafe { addr_of_mut!(RX_STORAGE.0) as u64 };
    let Some(rx_phys) = page_tables.translate_kernel_va(rx_va) else {
        return false;
    };
    if rx_phys > u32::MAX as u64 {
        return false;
    }

    let driver = unsafe { &mut *addr_of_mut!(DRIVER) };
    driver.state = EMPTY_SNAPSHOT;
    driver.state.device = true;
    driver.state.pci_bus = bus;
    driver.state.pci_device = device;
    driver.state.io_base = io_base;
    driver.rx_offset = 0;
    driver.tx_slot = 0;
    driver.offered_ip = [0; 4];
    driver.neighbor_ip = [0; 4];
    driver.neighbor_mac = [0; 6];
    driver.ping_sequence = 0;
    driver.dns_pending = false;
    driver.dns_answer = [0; 4];
    reset_tcp(driver);

    for slot in 0..TX_SLOTS {
        let va = unsafe { addr_of_mut!(TX_STORAGE.0[slot][0]) as u64 };
        let Some(phys) = page_tables.translate_kernel_va(va) else {
            return false;
        };
        if phys > u32::MAX as u64 {
            return false;
        }
        driver.tx_phys[slot] = phys as u32;
    }

    // SAFETY: the PCI probe identified an RTL8139 I/O BAR owned by this driver.
    unsafe {
        io::outb(io_base + REG_CONFIG1, 0x00);
        io::outb(io_base + REG_COMMAND, 0x10);
        for _ in 0..100_000 {
            if io::inb(io_base + REG_COMMAND) & 0x10 == 0 {
                break;
            }
            io::cpu_relax();
        }
        io::outl(io_base + REG_RBSTART, rx_phys as u32);
        io::outw(io_base + REG_IMR, 0);
        io::outw(io_base + REG_ISR, 0xffff);
        io::outl(io_base + REG_RCR, 0x0000_008a);
        io::outb(io_base + REG_COMMAND, 0x0c);
        for index in 0..6 {
            driver.state.mac[index] = io::inb(io_base + index as u16);
        }
        driver.state.link = io::inb(io_base + REG_MEDIA_STATUS) & 0x04 == 0;
    }

    driver.state.dhcp = DhcpState::Discovering;
    send_dhcp(driver, 1);
    let deadline = arch::timer_ticks().saturating_add(5 * arch::TIMER_HZ);
    while arch::timer_ticks() < deadline && driver.state.dhcp != DhcpState::Bound {
        poll_driver(driver);
        io::cpu_relax();
    }
    if driver.state.dhcp != DhcpState::Bound {
        driver.state.dhcp = DhcpState::TimedOut;
    }
    true
}

pub fn poll() {
    let driver = unsafe { &mut *addr_of_mut!(DRIVER) };
    if driver.state.device {
        poll_driver(driver);
    }
}

pub fn configured() -> bool {
    unsafe { (*addr_of!(DRIVER)).state.dhcp == DhcpState::Bound }
}

pub fn snapshot() -> Snapshot {
    unsafe { (*addr_of!(DRIVER)).state }
}

pub fn ssh_listening() -> bool {
    let driver = unsafe { &*addr_of!(DRIVER) };
    driver.state.dhcp == DhcpState::Bound
}

pub fn tcp_connected() -> bool {
    let driver = unsafe { &*addr_of!(DRIVER) };
    matches!(driver.tcp_state, TcpState::Established)
}

pub fn tcp_read(output: &mut [u8]) -> usize {
    let driver = unsafe { &mut *addr_of_mut!(DRIVER) };
    let count = output.len().min(driver.tcp_rx_len);
    output[..count].copy_from_slice(&driver.tcp_rx[..count]);
    driver.tcp_rx.copy_within(count..driver.tcp_rx_len, 0);
    driver.tcp_rx_len -= count;
    count
}

pub fn tcp_write(bytes: &[u8]) -> bool {
    let driver = unsafe { &mut *addr_of_mut!(DRIVER) };
    if driver.tcp_state != TcpState::Established {
        return false;
    }
    for chunk in bytes.chunks(TCP_MSS) {
        let sequence = driver.tcp_send_next;
        if !send_tcp(driver, 0x18, chunk) {
            return false;
        }
        driver.tcp_send_next = driver.tcp_send_next.wrapping_add(chunk.len() as u32);
        let deadline = arch::timer_ticks().saturating_add(2 * arch::TIMER_HZ);
        while (driver.tcp_send_una.wrapping_sub(driver.tcp_send_next) as i32) < 0
            && arch::timer_ticks() < deadline
            && driver.tcp_state == TcpState::Established
        {
            poll_driver(driver);
            io::cpu_relax();
        }
        if (driver.tcp_send_una.wrapping_sub(driver.tcp_send_next) as i32) < 0 {
            // One retransmission is enough for the current single-hop QEMU target.
            driver.tcp_send_next = sequence;
            if !send_tcp(driver, 0x18, chunk) {
                return false;
            }
            driver.tcp_send_next = sequence.wrapping_add(chunk.len() as u32);
        }
    }
    true
}

pub fn tcp_reset() {
    let driver = unsafe { &mut *addr_of_mut!(DRIVER) };
    reset_tcp(driver);
}

pub fn ping(target: &[u8]) -> Result<PingResult, PingError> {
    let driver = unsafe { &mut *addr_of_mut!(DRIVER) };
    if driver.state.dhcp != DhcpState::Bound {
        return Err(PingError::NetworkUnavailable);
    }
    let address = if target.is_empty() {
        driver.state.gateway
    } else if let Some(address) = parse_ipv4(target) {
        address
    } else {
        resolve(driver, target)?
    };
    let next_hop = if same_subnet(address, driver.state.ipv4, driver.state.netmask) {
        address
    } else {
        driver.state.gateway
    };
    if !ensure_neighbor(driver, next_hop) {
        return Err(PingError::NeighborTimeout);
    }
    driver.ping_sequence = driver.ping_sequence.wrapping_add(1);
    let sequence = driver.ping_sequence;
    let mut frame = [0u8; 58];
    frame[0..6].copy_from_slice(&driver.neighbor_mac);
    frame[6..12].copy_from_slice(&driver.state.mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&44u16.to_be_bytes());
    frame[ip + 4..ip + 6].copy_from_slice(&sequence.to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 1;
    frame[ip + 12..ip + 16].copy_from_slice(&driver.state.ipv4);
    frame[ip + 16..ip + 20].copy_from_slice(&address);
    let ip_sum = checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_sum.to_be_bytes());
    let icmp = ip + 20;
    frame[icmp] = 8;
    frame[icmp + 4..icmp + 6].copy_from_slice(&0x4f52u16.to_be_bytes());
    frame[icmp + 6..icmp + 8].copy_from_slice(&sequence.to_be_bytes());
    frame[icmp + 8..icmp + 24].copy_from_slice(b"ORYVAEL-NET-PING");
    let icmp_sum = checksum(&frame[icmp..]);
    frame[icmp + 2..icmp + 4].copy_from_slice(&icmp_sum.to_be_bytes());

    let before = driver.state.ping_replies;
    let started = arch::timer_ticks();
    if !send_frame(driver, &frame) {
        return Err(PingError::EchoTimeout);
    }
    let deadline = started.saturating_add(2 * arch::TIMER_HZ);
    while arch::timer_ticks() < deadline {
        poll_driver(driver);
        if driver.state.ping_replies != before {
            let elapsed = arch::timer_ticks().saturating_sub(started);
            driver.state.ping_rtt_ticks = elapsed;
            return Ok(PingResult {
                address,
                milliseconds: elapsed.saturating_mul(1000) / arch::TIMER_HZ,
            });
        }
        io::cpu_relax();
    }
    Err(PingError::EchoTimeout)
}

fn ensure_neighbor(driver: &mut Driver, address: [u8; 4]) -> bool {
    if driver.neighbor_ip == address {
        return true;
    }
    driver.neighbor_ip = [0; 4];
    driver.neighbor_mac = [0; 6];
    send_arp_request(driver, address);
    let deadline = arch::timer_ticks().saturating_add(arch::TIMER_HZ);
    while arch::timer_ticks() < deadline && driver.neighbor_ip != address {
        poll_driver(driver);
        io::cpu_relax();
    }
    driver.neighbor_ip == address
}

fn resolve(driver: &mut Driver, name: &[u8]) -> Result<[u8; 4], PingError> {
    if name.is_empty() || name.len() > 253 || driver.state.dns == [0; 4] {
        return Err(PingError::InvalidName);
    }
    let next_hop = if same_subnet(driver.state.dns, driver.state.ipv4, driver.state.netmask) {
        driver.state.dns
    } else {
        driver.state.gateway
    };
    if !ensure_neighbor(driver, next_hop) {
        return Err(PingError::NeighborTimeout);
    }
    driver.dns_pending = true;
    driver.dns_answer = [0; 4];
    if !send_dns_query(driver, name) {
        driver.dns_pending = false;
        return Err(PingError::InvalidName);
    }
    let deadline = arch::timer_ticks().saturating_add(2 * arch::TIMER_HZ);
    while arch::timer_ticks() < deadline && driver.dns_pending {
        poll_driver(driver);
        io::cpu_relax();
    }
    if driver.dns_answer == [0; 4] {
        Err(PingError::DnsTimeout)
    } else {
        Ok(driver.dns_answer)
    }
}

fn find_rtl8139() -> Option<(u8, u8, u16)> {
    for bus in 0u16..=255 {
        for device in 0u8..32 {
            let id = pci_read(bus as u8, device, 0, 0);
            if id as u16 == RTL_VENDOR && (id >> 16) as u16 == RTL_DEVICE {
                let bar = pci_read(bus as u8, device, 0, 0x10);
                if bar & 1 == 0 {
                    return None;
                }
                let command = pci_read(bus as u8, device, 0, 0x04);
                pci_write(bus as u8, device, 0, 0x04, command | 0x5);
                return Some((bus as u8, device, (bar & 0xfffc) as u16));
            }
        }
    }
    None
}

fn pci_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = 0x8000_0000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xfc);
    unsafe {
        io::outl(0xcf8, address);
        io::inl(0xcfc)
    }
}

fn pci_write(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = 0x8000_0000
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xfc);
    unsafe {
        io::outl(0xcf8, address);
        io::outl(0xcfc, value);
    }
}

fn poll_driver(driver: &mut Driver) {
    let base = driver.state.io_base;
    for _ in 0..32 {
        let empty = unsafe { io::inb(base + REG_COMMAND) & 0x01 != 0 };
        if empty {
            break;
        }
        let ring = unsafe { addr_of_mut!(RX_STORAGE.0) as *mut u8 };
        let header = unsafe { ring.add(driver.rx_offset) };
        let status = unsafe { read_volatile(header.cast::<u16>()) };
        let length = unsafe { read_volatile(header.add(2).cast::<u16>()) } as usize;
        if status & 1 == 0 || !(4..=FRAME_BYTES + 4).contains(&length) {
            driver.state.dropped = driver.state.dropped.saturating_add(1);
            driver.rx_offset = (driver.rx_offset + length.max(4) + 4 + 3) & !3;
            driver.rx_offset %= RX_BYTES;
        } else {
            let frame_len = length - 4;
            let frame = unsafe { core::slice::from_raw_parts(header.add(4), frame_len) };
            driver.state.rx_packets = driver.state.rx_packets.saturating_add(1);
            driver.state.rx_bytes = driver.state.rx_bytes.saturating_add(frame_len as u64);
            handle_frame(driver, frame);
            driver.rx_offset = (driver.rx_offset + length + 4 + 3) & !3;
            driver.rx_offset %= RX_BYTES;
        }
        unsafe { io::outw(base + REG_CAPR, driver.rx_offset.wrapping_sub(16) as u16) };
    }
    unsafe { io::outw(base + REG_ISR, 0xffff) };
}

fn handle_frame(driver: &mut Driver, frame: &[u8]) {
    if frame.len() < 14 {
        driver.state.dropped = driver.state.dropped.saturating_add(1);
        return;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0806 => handle_arp(driver, frame),
        0x0800 => handle_ipv4(driver, frame),
        _ => {}
    }
}

fn handle_arp(driver: &mut Driver, frame: &[u8]) {
    if frame.len() < 42 || frame[14..20] != [0, 1, 8, 0, 6, 4] {
        return;
    }
    let operation = u16::from_be_bytes([frame[20], frame[21]]);
    let sender_mac: [u8; 6] = frame[22..28].try_into().unwrap_or([0; 6]);
    let sender_ip: [u8; 4] = frame[28..32].try_into().unwrap_or([0; 4]);
    let target_ip = [frame[38], frame[39], frame[40], frame[41]];
    if operation == 2 {
        driver.state.arp_responses = driver.state.arp_responses.saturating_add(1);
        driver.neighbor_ip = sender_ip;
        driver.neighbor_mac = sender_mac;
    }
    if operation != 1 || target_ip != driver.state.ipv4 || driver.state.dhcp != DhcpState::Bound {
        return;
    }
    driver.state.arp_requests = driver.state.arp_requests.saturating_add(1);
    let mut reply = [0u8; 42];
    reply[0..6].copy_from_slice(&frame[6..12]);
    reply[6..12].copy_from_slice(&driver.state.mac);
    reply[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    reply[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
    reply[22..28].copy_from_slice(&driver.state.mac);
    reply[28..32].copy_from_slice(&driver.state.ipv4);
    reply[32..38].copy_from_slice(&frame[22..28]);
    reply[38..42].copy_from_slice(&frame[28..32]);
    if send_frame(driver, &reply) {
        driver.state.arp_replies = driver.state.arp_replies.saturating_add(1);
    }
}

fn handle_ipv4(driver: &mut Driver, frame: &[u8]) {
    if frame.len() < 34 || frame[14] >> 4 != 4 {
        return;
    }
    let ihl = ((frame[14] & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < 14 + ihl || checksum(&frame[14..14 + ihl]) != 0 {
        driver.state.dropped = driver.state.dropped.saturating_add(1);
        return;
    }
    match frame[23] {
        1 => handle_icmp(driver, frame, ihl),
        6 => handle_tcp(driver, frame, ihl),
        17 => handle_udp(driver, frame, ihl),
        _ => {}
    }
}

fn handle_tcp(driver: &mut Driver, frame: &[u8], ihl: usize) {
    let ip = 14;
    let tcp = ip + ihl;
    let total = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]) as usize;
    if frame.len() < ip + total || total < ihl + 20 || tcp + 20 > frame.len() {
        return;
    }
    if frame[ip + 16..ip + 20] != driver.state.ipv4 {
        return;
    }
    let source_port = u16::from_be_bytes([frame[tcp], frame[tcp + 1]]);
    let destination_port = u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]);
    if destination_port != SSH_PORT {
        return;
    }
    let header_len = ((frame[tcp + 12] >> 4) as usize) * 4;
    if header_len < 20 || total < ihl + header_len {
        return;
    }
    let source_ip: [u8; 4] = frame[ip + 12..ip + 16].try_into().unwrap_or([0; 4]);
    if tcp_checksum(source_ip, driver.state.ipv4, &frame[tcp..ip + total]) != 0 {
        driver.state.dropped = driver.state.dropped.saturating_add(1);
        return;
    }
    let sequence = u32::from_be_bytes(frame[tcp + 4..tcp + 8].try_into().unwrap_or([0; 4]));
    let acknowledgement = u32::from_be_bytes(frame[tcp + 8..tcp + 12].try_into().unwrap_or([0; 4]));
    let flags = frame[tcp + 13];

    if flags & 0x04 != 0 {
        reset_tcp(driver);
        return;
    }
    if flags & 0x02 != 0 {
        if driver.tcp_state != TcpState::Listen {
            reset_tcp(driver);
        }
        driver.tcp_remote_mac.copy_from_slice(&frame[6..12]);
        driver.tcp_remote_ip = source_ip;
        driver.tcp_remote_port = source_port;
        driver.tcp_recv_next = sequence.wrapping_add(1);
        let initial = 0x4f52_0000u32 ^ arch::timer_ticks() as u32;
        driver.tcp_send_next = initial;
        driver.tcp_send_una = initial;
        driver.tcp_state = TcpState::SynReceived;
        if send_tcp(driver, 0x12, &[]) {
            driver.tcp_send_next = driver.tcp_send_next.wrapping_add(1);
        }
        return;
    }
    if source_ip != driver.tcp_remote_ip || source_port != driver.tcp_remote_port {
        return;
    }
    if flags & 0x10 != 0
        && acknowledgement.wrapping_sub(driver.tcp_send_una) as i32 >= 0
        && driver.tcp_send_next.wrapping_sub(acknowledgement) as i32 >= 0
    {
        driver.tcp_send_una = acknowledgement;
        if driver.tcp_state == TcpState::SynReceived && acknowledgement == driver.tcp_send_next {
            driver.tcp_state = TcpState::Established;
        } else if driver.tcp_state == TcpState::LastAck && acknowledgement == driver.tcp_send_next {
            reset_tcp(driver);
            return;
        }
    }

    let payload_start = tcp + header_len;
    let payload_len = ip + total - payload_start;
    if payload_len != 0 && driver.tcp_state == TcpState::Established {
        if sequence == driver.tcp_recv_next {
            let available = TCP_RX_BYTES - driver.tcp_rx_len;
            let accepted = payload_len.min(available);
            driver.tcp_rx[driver.tcp_rx_len..driver.tcp_rx_len + accepted]
                .copy_from_slice(&frame[payload_start..payload_start + accepted]);
            driver.tcp_rx_len += accepted;
            driver.tcp_recv_next = driver.tcp_recv_next.wrapping_add(accepted as u32);
        }
        send_tcp(driver, 0x10, &[]);
    }

    if flags & 0x01 != 0 {
        let fin_sequence = sequence.wrapping_add(payload_len as u32);
        if fin_sequence == driver.tcp_recv_next {
            driver.tcp_recv_next = driver.tcp_recv_next.wrapping_add(1);
        }
        send_tcp(driver, 0x10, &[]);
        if driver.tcp_state == TcpState::Established {
            if send_tcp(driver, 0x11, &[]) {
                driver.tcp_send_next = driver.tcp_send_next.wrapping_add(1);
                driver.tcp_state = TcpState::LastAck;
            }
        }
    }
}

fn send_tcp(driver: &mut Driver, flags: u8, payload: &[u8]) -> bool {
    if payload.len() > TCP_MSS {
        return false;
    }
    let mut frame = [0u8; FRAME_BYTES];
    let length = 14 + 20 + 20 + payload.len();
    frame[0..6].copy_from_slice(&driver.tcp_remote_mac);
    frame[6..12].copy_from_slice(&driver.state.mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = 14;
    frame[ip] = 0x45;
    frame[ip + 2..ip + 4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    frame[ip + 4..ip + 6].copy_from_slice(&(arch::timer_ticks() as u16).to_be_bytes());
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 6;
    frame[ip + 12..ip + 16].copy_from_slice(&driver.state.ipv4);
    frame[ip + 16..ip + 20].copy_from_slice(&driver.tcp_remote_ip);
    let ip_sum = checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&ip_sum.to_be_bytes());

    let tcp = ip + 20;
    frame[tcp..tcp + 2].copy_from_slice(&SSH_PORT.to_be_bytes());
    frame[tcp + 2..tcp + 4].copy_from_slice(&driver.tcp_remote_port.to_be_bytes());
    frame[tcp + 4..tcp + 8].copy_from_slice(&driver.tcp_send_next.to_be_bytes());
    frame[tcp + 8..tcp + 12].copy_from_slice(&driver.tcp_recv_next.to_be_bytes());
    frame[tcp + 12] = 5 << 4;
    frame[tcp + 13] = flags;
    let window = (TCP_RX_BYTES - driver.tcp_rx_len).min(u16::MAX as usize) as u16;
    frame[tcp + 14..tcp + 16].copy_from_slice(&window.to_be_bytes());
    frame[tcp + 20..length].copy_from_slice(payload);
    let tcp_sum = tcp_checksum(driver.state.ipv4, driver.tcp_remote_ip, &frame[tcp..length]);
    frame[tcp + 16..tcp + 18].copy_from_slice(&tcp_sum.to_be_bytes());
    send_frame(driver, &frame[..length])
}

fn tcp_checksum(source: [u8; 4], destination: [u8; 4], segment: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = checksum_add(sum, &source);
    sum = checksum_add(sum, &destination);
    sum += 6;
    sum += segment.len() as u32;
    sum = checksum_add(sum, segment);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_add(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut index = 0;
    while index + 1 < bytes.len() {
        sum += u16::from_be_bytes([bytes[index], bytes[index + 1]]) as u32;
        index += 2;
    }
    if index < bytes.len() {
        sum += (bytes[index] as u32) << 8;
    }
    sum
}

fn reset_tcp(driver: &mut Driver) {
    driver.tcp_state = TcpState::Listen;
    driver.tcp_remote_mac = [0; 6];
    driver.tcp_remote_ip = [0; 4];
    driver.tcp_remote_port = 0;
    driver.tcp_send_next = 0;
    driver.tcp_send_una = 0;
    driver.tcp_recv_next = 0;
    driver.tcp_rx_len = 0;
}

fn handle_udp(driver: &mut Driver, frame: &[u8], ihl: usize) {
    let udp = 14 + ihl;
    if frame.len() < udp + 8 {
        return;
    }
    let source = u16::from_be_bytes([frame[udp], frame[udp + 1]]);
    let destination = u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]);
    if destination == 68 {
        handle_dhcp(driver, frame, ihl);
    } else if source == 53 && destination == DNS_PORT {
        handle_dns(driver, &frame[udp + 8..]);
    }
}

fn handle_icmp(driver: &mut Driver, frame: &[u8], ihl: usize) {
    let ip = 14;
    let icmp = ip + ihl;
    let total = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]) as usize;
    if frame.len() < ip + total || total < ihl + 8 {
        return;
    }
    if frame[ip + 16..ip + 20] != driver.state.ipv4 {
        return;
    }
    let icmp_len = total - ihl;
    if checksum(&frame[icmp..icmp + icmp_len]) != 0 || ip + total > FRAME_BYTES {
        driver.state.dropped = driver.state.dropped.saturating_add(1);
        return;
    }
    if frame[icmp] == 0 && frame[icmp + 4..icmp + 6] == 0x4f52u16.to_be_bytes() {
        driver.state.ping_replies = driver.state.ping_replies.saturating_add(1);
        return;
    }
    if frame[icmp] != 8 {
        return;
    }
    driver.state.icmp_requests = driver.state.icmp_requests.saturating_add(1);
    let mut reply = [0u8; FRAME_BYTES];
    let length = ip + total;
    reply[..length].copy_from_slice(&frame[..length]);
    reply[0..6].copy_from_slice(&frame[6..12]);
    reply[6..12].copy_from_slice(&driver.state.mac);
    reply[ip + 12..ip + 16].copy_from_slice(&driver.state.ipv4);
    reply[ip + 16..ip + 20].copy_from_slice(&frame[ip + 12..ip + 16]);
    reply[ip + 8] = 64;
    reply[ip + 10..ip + 12].fill(0);
    let ip_sum = checksum(&reply[ip..ip + ihl]);
    reply[ip + 10..ip + 12].copy_from_slice(&ip_sum.to_be_bytes());
    reply[icmp] = 0;
    reply[icmp + 2..icmp + 4].fill(0);
    let icmp_sum = checksum(&reply[icmp..icmp + icmp_len]);
    reply[icmp + 2..icmp + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    if send_frame(driver, &reply[..length]) {
        driver.state.icmp_replies = driver.state.icmp_replies.saturating_add(1);
    }
}

fn send_arp_request(driver: &mut Driver, target: [u8; 4]) {
    let mut frame = [0u8; 42];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&driver.state.mac);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    frame[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&driver.state.mac);
    frame[28..32].copy_from_slice(&driver.state.ipv4);
    frame[38..42].copy_from_slice(&target);
    if send_frame(driver, &frame) {
        driver.state.arp_queries = driver.state.arp_queries.saturating_add(1);
    }
}

fn handle_dhcp(driver: &mut Driver, frame: &[u8], ihl: usize) {
    let udp = 14 + ihl;
    if frame.len() < udp + 8 + 240 {
        return;
    }
    if u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]) != 68 {
        return;
    }
    let bootp = udp + 8;
    if frame[bootp] != 2
        || u32::from_be_bytes(frame[bootp + 4..bootp + 8].try_into().unwrap_or([0; 4])) != DHCP_XID
        || frame[bootp + 28..bootp + 34] != driver.state.mac
        || frame[bootp + 236..bootp + 240] != [99, 130, 83, 99]
    {
        return;
    }
    let offered_ip: [u8; 4] = frame[bootp + 16..bootp + 20].try_into().unwrap_or([0; 4]);
    let mut message_type = 0u8;
    let mut server = [0u8; 4];
    let mut mask = [0u8; 4];
    let mut router = [0u8; 4];
    let mut dns = [0u8; 4];
    let mut lease = 0u32;
    let mut pos = bootp + 240;
    while pos < frame.len() {
        let code = frame[pos];
        pos += 1;
        if code == 255 {
            break;
        }
        if code == 0 {
            continue;
        }
        if pos >= frame.len() {
            break;
        }
        let len = frame[pos] as usize;
        pos += 1;
        if pos + len > frame.len() {
            break;
        }
        match (code, len) {
            (53, 1) => message_type = frame[pos],
            (54, 4) => server.copy_from_slice(&frame[pos..pos + 4]),
            (1, 4) => mask.copy_from_slice(&frame[pos..pos + 4]),
            (3, n) if n >= 4 => router.copy_from_slice(&frame[pos..pos + 4]),
            (6, n) if n >= 4 => dns.copy_from_slice(&frame[pos..pos + 4]),
            (51, 4) => lease = u32::from_be_bytes(frame[pos..pos + 4].try_into().unwrap_or([0; 4])),
            _ => {}
        }
        pos += len;
    }
    if message_type == 2 && driver.state.dhcp == DhcpState::Discovering {
        driver.offered_ip = offered_ip;
        driver.state.dhcp_server = server;
        driver.state.netmask = mask;
        driver.state.gateway = router;
        driver.state.dns = dns;
        driver.state.lease_seconds = lease;
        driver.state.dhcp = DhcpState::Requesting;
        send_dhcp(driver, 3);
    } else if message_type == 5 && driver.state.dhcp == DhcpState::Requesting {
        driver.state.ipv4 = offered_ip;
        driver.state.dhcp_server = server;
        driver.state.netmask = mask;
        driver.state.gateway = router;
        driver.state.dns = dns;
        driver.state.lease_seconds = lease;
        driver.state.dhcp = DhcpState::Bound;
    }
}

fn handle_dns(driver: &mut Driver, dns: &[u8]) {
    if !driver.dns_pending || dns.len() < 12 {
        return;
    }
    if u16::from_be_bytes([dns[0], dns[1]]) != DNS_ID || dns[2] & 0x80 == 0 {
        return;
    }
    let questions = u16::from_be_bytes([dns[4], dns[5]]) as usize;
    let answers = u16::from_be_bytes([dns[6], dns[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..questions {
        let Some(next) = skip_dns_name(dns, pos) else {
            return;
        };
        pos = next;
        if pos + 4 > dns.len() {
            return;
        }
        pos += 4;
    }
    for _ in 0..answers {
        let Some(next) = skip_dns_name(dns, pos) else {
            return;
        };
        pos = next;
        if pos + 10 > dns.len() {
            return;
        }
        let record_type = u16::from_be_bytes([dns[pos], dns[pos + 1]]);
        let class = u16::from_be_bytes([dns[pos + 2], dns[pos + 3]]);
        let length = u16::from_be_bytes([dns[pos + 8], dns[pos + 9]]) as usize;
        pos += 10;
        if pos + length > dns.len() {
            return;
        }
        if record_type == 1 && class == 1 && length == 4 {
            driver.dns_answer.copy_from_slice(&dns[pos..pos + 4]);
            driver.dns_pending = false;
            driver.state.dns_replies = driver.state.dns_replies.saturating_add(1);
            return;
        }
        pos += length;
    }
    driver.dns_pending = false;
}

fn skip_dns_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let length = *packet.get(pos)? as usize;
        pos += 1;
        if length == 0 {
            return Some(pos);
        }
        if length & 0xc0 == 0xc0 {
            packet.get(pos)?;
            return Some(pos + 1);
        }
        if length > 63 || pos.checked_add(length)? > packet.len() {
            return None;
        }
        pos += length;
    }
}

fn send_dns_query(driver: &mut Driver, name: &[u8]) -> bool {
    let mut frame = [0u8; 512];
    frame[0..6].copy_from_slice(&driver.neighbor_mac);
    frame[6..12].copy_from_slice(&driver.state.mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = 14;
    let udp = ip + 20;
    let dns = udp + 8;
    frame[ip] = 0x45;
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 17;
    frame[ip + 12..ip + 16].copy_from_slice(&driver.state.ipv4);
    frame[ip + 16..ip + 20].copy_from_slice(&driver.state.dns);
    frame[udp..udp + 2].copy_from_slice(&DNS_PORT.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&53u16.to_be_bytes());
    frame[dns..dns + 2].copy_from_slice(&DNS_ID.to_be_bytes());
    frame[dns + 2..dns + 4].copy_from_slice(&0x0100u16.to_be_bytes());
    frame[dns + 4..dns + 6].copy_from_slice(&1u16.to_be_bytes());
    let mut pos = dns + 12;
    for label in name.split(|byte| *byte == b'.') {
        if label.is_empty() || label.len() > 63 || pos + 1 + label.len() + 5 > frame.len() {
            return false;
        }
        frame[pos] = label.len() as u8;
        pos += 1;
        frame[pos..pos + label.len()].copy_from_slice(label);
        pos += label.len();
    }
    frame[pos] = 0;
    pos += 1;
    frame[pos..pos + 4].copy_from_slice(&[0, 1, 0, 1]);
    pos += 4;
    let dns_len = pos - dns;
    let udp_len = 8 + dns_len;
    let ip_len = 20 + udp_len;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let sum = checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&sum.to_be_bytes());
    if send_frame(driver, &frame[..14 + ip_len]) {
        driver.state.dns_queries = driver.state.dns_queries.saturating_add(1);
        true
    } else {
        false
    }
}

fn send_dhcp(driver: &mut Driver, message_type: u8) {
    let mut frame = [0u8; 600];
    frame[0..6].fill(0xff);
    frame[6..12].copy_from_slice(&driver.state.mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = 14;
    let udp = ip + 20;
    let bootp = udp + 8;
    frame[ip] = 0x45;
    frame[ip + 6..ip + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[ip + 8] = 64;
    frame[ip + 9] = 17;
    frame[ip + 16..ip + 20].fill(0xff);
    frame[udp..udp + 2].copy_from_slice(&68u16.to_be_bytes());
    frame[udp + 2..udp + 4].copy_from_slice(&67u16.to_be_bytes());
    frame[bootp] = 1;
    frame[bootp + 1] = 1;
    frame[bootp + 2] = 6;
    frame[bootp + 4..bootp + 8].copy_from_slice(&DHCP_XID.to_be_bytes());
    frame[bootp + 10..bootp + 12].copy_from_slice(&0x8000u16.to_be_bytes());
    frame[bootp + 28..bootp + 34].copy_from_slice(&driver.state.mac);
    frame[bootp + 236..bootp + 240].copy_from_slice(&[99, 130, 83, 99]);
    let mut pos = bootp + 240;
    frame[pos..pos + 3].copy_from_slice(&[53, 1, message_type]);
    pos += 3;
    frame[pos..pos + 9].copy_from_slice(&[55, 7, 1, 3, 6, 15, 51, 54, 58]);
    pos += 9;
    if message_type == 3 {
        frame[pos..pos + 6].copy_from_slice(&[50, 4, 0, 0, 0, 0]);
        frame[pos + 2..pos + 6].copy_from_slice(&driver.offered_ip);
        pos += 6;
        frame[pos..pos + 6].copy_from_slice(&[54, 4, 0, 0, 0, 0]);
        frame[pos + 2..pos + 6].copy_from_slice(&driver.state.dhcp_server);
        pos += 6;
    }
    frame[pos] = 255;
    pos += 1;
    let dhcp_len = pos - bootp;
    let udp_len = 8 + dhcp_len;
    let ip_len = 20 + udp_len;
    frame[ip + 2..ip + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
    frame[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let sum = checksum(&frame[ip..ip + 20]);
    frame[ip + 10..ip + 12].copy_from_slice(&sum.to_be_bytes());
    send_frame(driver, &frame[..14 + ip_len]);
}

fn send_frame(driver: &mut Driver, frame: &[u8]) -> bool {
    if frame.len() > FRAME_BYTES {
        driver.state.dropped = driver.state.dropped.saturating_add(1);
        return false;
    }
    let slot = driver.tx_slot;
    let tsd = driver.state.io_base + REG_TSD0 + (slot as u16 * 4);
    let ready = unsafe { io::inl(tsd) & (1 << 13) != 0 };
    if !ready {
        driver.state.dropped = driver.state.dropped.saturating_add(1);
        return false;
    }
    unsafe {
        let destination = addr_of_mut!(TX_STORAGE.0[slot][0]);
        core::ptr::copy_nonoverlapping(frame.as_ptr(), destination, frame.len());
        io::outl(
            driver.state.io_base + REG_TSAD0 + (slot as u16 * 4),
            driver.tx_phys[slot],
        );
        io::outl(tsd, frame.len() as u32);
    }
    driver.tx_slot = (slot + 1) % TX_SLOTS;
    driver.state.tx_packets = driver.state.tx_packets.saturating_add(1);
    driver.state.tx_bytes = driver.state.tx_bytes.saturating_add(frame.len() as u64);
    true
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add((last as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn same_subnet(left: [u8; 4], right: [u8; 4], mask: [u8; 4]) -> bool {
    (0..4).all(|index| left[index] & mask[index] == right[index] & mask[index])
}

fn parse_ipv4(text: &[u8]) -> Option<[u8; 4]> {
    let mut address = [0u8; 4];
    let mut part = 0usize;
    let mut value = 0u16;
    let mut digits = 0usize;
    for &byte in text.iter().chain(core::iter::once(&b'.')) {
        if byte == b'.' {
            if digits == 0 || part >= 4 {
                return None;
            }
            address[part] = value as u8;
            part += 1;
            value = 0;
            digits = 0;
        } else if byte.is_ascii_digit() {
            value = value.checked_mul(10)?.checked_add((byte - b'0') as u16)?;
            if value > 255 {
                return None;
            }
            digits += 1;
        } else {
            return None;
        }
    }
    (part == 4).then_some(address)
}
