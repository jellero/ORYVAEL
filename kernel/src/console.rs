use crate::accounts;
use crate::arch;
use crate::boot::BootMemoryMap;
use crate::io::{self, KeyboardState};
use crate::memory::{FrameAllocator, KernelHeap, PAGE_SIZE, PageTables};
use crate::network::{self, DhcpState, PingError};
use crate::userspace;
use core::future::Future;

pub fn run(
    frames: &mut FrameAllocator,
    heap: &mut KernelHeap,
    page_tables: &PageTables,
    boot_map: &BootMemoryMap,
) -> ! {
    welcome(frames, heap, page_tables, boot_map);

    let mut keyboard = KeyboardState::new();
    let mut line = [0u8; 128];
    let mut length = 0usize;
    let mut last_was_cr = false;
    let mut ssh_task = core::pin::pin!(crate::ssh_server::run());
    prompt();

    loop {
        network::poll();
        let mut context = core::task::Context::from_waker(core::task::Waker::noop());
        let _ = ssh_task.as_mut().poll(&mut context);
        let byte = io::serial_try_read().or_else(|| keyboard.try_read_ascii());
        match byte {
            Some(b'\r') => {
                io::serial_write("\r\n");
                execute(&line[..length], frames, heap, page_tables, boot_map);
                length = 0;
                last_was_cr = true;
                prompt();
            }
            Some(b'\n') if last_was_cr => last_was_cr = false,
            Some(b'\n') => {
                io::serial_write("\r\n");
                execute(&line[..length], frames, heap, page_tables, boot_map);
                length = 0;
                prompt();
            }
            Some(0x08 | 0x7f) => {
                last_was_cr = false;
                if length != 0 {
                    length -= 1;
                    io::serial_write("\x08 \x08");
                }
            }
            Some(byte) if (0x20..=0x7e).contains(&byte) => {
                last_was_cr = false;
                if length < line.len() {
                    line[length] = byte;
                    length += 1;
                    io::serial_write_byte(byte);
                }
            }
            Some(_) => last_was_cr = false,
            None => io::cpu_relax(),
        }
    }
}

fn execute(
    line: &[u8],
    frames: &mut FrameAllocator,
    heap: &mut KernelHeap,
    page_tables: &PageTables,
    boot_map: &BootMemoryMap,
) {
    let command = trim_ascii(line);
    if command.is_empty() {
        return;
    }

    match command {
        b"help" => help(),
        b"status" => status(frames, heap, page_tables, boot_map),
        b"debug" => debug(frames, heap, page_tables, boot_map),
        b"ip" | b"ip -a" => ip_status(),
        b"net" | b"net debug" => network_status(),
        b"ping" => ping_target(&[]),
        value if value.starts_with(b"ping ") => ping_target(trim_ascii(&value[5..])),
        b"users" => users(),
        b"whoami" => whoami(),
        b"ssh" | b"ssh status" => ssh_status(),
        b"version" => version(),
        b"banner" => welcome(frames, heap, page_tables, boot_map),
        b"mem" => {
            io::serial_write("Memory snapshot\r\n");
            io::serial_write("  free.pages       ");
            io::serial_write_u64(frames.free_pages());
            io::serial_write("\r\n  free.mib         ");
            io::serial_write_u64(frames.free_pages().saturating_mul(PAGE_SIZE) / (1024 * 1024));
            io::serial_write("\r\n  heap.used.bytes  ");
            io::serial_write_u64(heap.used() as u64);
            io::serial_write("\r\n  heap.free.bytes  ");
            io::serial_write_u64(heap.free() as u64);
            io::serial_write("\r\n");
        }
        b"uptime" => {
            let ticks = arch::timer_ticks();
            io::serial_write("uptime: ticks=");
            io::serial_write_u64(ticks);
            io::serial_write(" seconds=");
            io::serial_write_u64(ticks / arch::TIMER_HZ);
            io::serial_write("\r\n");
        }
        b"alloc" => {
            io::serial_write("alloc: frame=");
            match frames.alloc_frame() {
                Some(frame) => io::serial_write_hex(frame),
                None => io::serial_write("none"),
            }
            io::serial_write(" heap64=");
            match heap.alloc(64, 16) {
                Some(address) => io::serial_write_hex(address as u64),
                None => io::serial_write("none"),
            }
            io::serial_write("\r\n");
        }
        b"vm" => {
            io::serial_write("Virtual memory\r\n");
            io::serial_write("  paging.cr3       ");
            io::serial_write_hex(page_tables.root_phys());
            io::serial_write("\r\n  userspace.base   ");
            io::serial_write_hex(userspace::USER_CODE_VA);
            io::serial_write("\r\n");
        }
        b"ps" => {
            io::serial_write("Process snapshot\r\n");
            io::serial_write("  init.state       exited\r\n");
            io::serial_write("  init.exit        ");
            io::serial_write_u64(userspace::exit_code());
            io::serial_write("\r\n  init.preemptions ");
            io::serial_write_u64(arch::user_preemptions());
            io::serial_write("\r\n");
        }
        b"fs" => {
            io::serial_write("ramfs: /hello -> ");
            io::serial_write_bytes(userspace::ramfs_hello());
        }
        b"ipc" => {
            let (full, value) = userspace::mailbox_state();
            io::serial_write("ipc: handle=0x1001 full=");
            io::serial_write(if full { "1" } else { "0" });
            io::serial_write(" last_value=");
            io::serial_write_u64(value);
            io::serial_write("\r\n");
        }
        b"clear" => io::serial_write("\x1b[2J\x1b[H"),
        b"about" => {
            io::serial_write("ORYVAEL is a sovereign AI-native operating system.\r\n");
            io::serial_write("Intelligence is powerful; authority remains explicitly human.\r\n");
        }
        b"reboot" => {
            io::serial_write("rebooting...\r\n");
            io::reboot();
        }
        _ => {
            io::serial_write("unknown command: ");
            io::serial_write_bytes(command);
            io::serial_write("\r\n");
        }
    }
}

fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first() == Some(&b' ') || bytes.first() == Some(&b'\t') {
        bytes = &bytes[1..];
    }
    while bytes.last() == Some(&b' ') || bytes.last() == Some(&b'\t') {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn prompt() {
    io::serial_write("\x1b[1;36moryvael\x1b[0m::\x1b[1;37msystem\x1b[0m> ");
}

fn welcome(
    frames: &FrameAllocator,
    heap: &KernelHeap,
    page_tables: &PageTables,
    boot_map: &BootMemoryMap,
) {
    io::serial_write("\r\n");
    io::serial_write("\x1b[1;36m+----------------------------------------------------------+\r\n");
    io::serial_write("|                 Welcome to ORYVAEL                       |\r\n");
    io::serial_write("+----------------------------------------------------------+\x1b[0m\r\n");
    io::serial_write("  Native system:  online\r\n");
    io::serial_write("  Architecture:   x86_64 / UEFI / ring 3\r\n");
    io::serial_write("  Security model: capability-first, human-authorized\r\n");
    io::serial_write("  Memory free:    ");
    io::serial_write_u64(frames.free_pages().saturating_mul(PAGE_SIZE) / (1024 * 1024));
    io::serial_write(" MiB\r\n");
    io::serial_write("  Memory regions: ");
    io::serial_write_u64(frames.region_count() as u64);
    io::serial_write(" usable / ");
    io::serial_write_u64(boot_map.descriptors as u64);
    io::serial_write(" firmware descriptors\r\n");
    io::serial_write("  Kernel heap:    ");
    io::serial_write_u64(heap.capacity() as u64 / 1024);
    io::serial_write(" KiB\r\n");
    io::serial_write("  Address space:  ");
    io::serial_write_hex(page_tables.root_phys());
    io::serial_write("\r\n\r\n");
    io::serial_write("  Type \x1b[1mhelp\x1b[0m to explore the system.\r\n\r\n");
}

fn help() {
    io::serial_write("\r\n\x1b[1;36mORYVAEL command center\x1b[0m\r\n");
    io::serial_write("  status   system overview       mem      memory statistics\r\n");
    io::serial_write("  uptime   kernel uptime         vm       address-space state\r\n");
    io::serial_write("  ps       process state         fs       RAM filesystem\r\n");
    io::serial_write("  ipc      capability mailbox    alloc    allocator probe\r\n");
    io::serial_write("  debug    kernel diagnostics    ip       address summary\r\n");
    io::serial_write("  net      network diagnostics  ping     gateway probe\r\n");
    io::serial_write("  ping HOST  DNS lookup and ICMP echo\r\n");
    io::serial_write("  users    account registry     whoami   active identity\r\n");
    io::serial_write("  ssh      secure-shell status\r\n");
    io::serial_write("  version  build identity        banner   show welcome\r\n");
    io::serial_write("  about    project mission       clear    clear console\r\n");
    io::serial_write("  reboot   restart the machine\r\n\r\n");
}

fn version() {
    io::serial_write("ORYVAEL 0.0.2-dev | native x86_64 kernel | UEFI stage 2\r\n");
}

fn users() {
    io::serial_write("\r\n\x1b[1;36mAccount registry\x1b[0m\r\n");
    io::serial_write("  UID    NAME       ROLE                 SSH\r\n");
    io::serial_write("  -----  ---------  -------------------  --------\r\n");
    for account in accounts::all() {
        io::serial_write("  ");
        io::serial_write_u64(account.uid as u64);
        for _ in 0..(7usize.saturating_sub(decimal_width(account.uid))) {
            io::serial_write_byte(b' ');
        }
        io::serial_write(account.name);
        for _ in 0..(11usize.saturating_sub(account.name.len())) {
            io::serial_write_byte(b' ');
        }
        io::serial_write(account.role);
        for _ in 0..(21usize.saturating_sub(account.role.len())) {
            io::serial_write_byte(b' ');
        }
        io::serial_write(if account.ssh_login {
            "enabled"
        } else {
            "disabled"
        });
        io::serial_write("\r\n");
    }
    io::serial_write("\r\n");
}

fn whoami() {
    let account = accounts::current();
    io::serial_write("identity\r\n");
    io::serial_write("  name           ");
    io::serial_write(account.name);
    io::serial_write("\r\n  uid            ");
    io::serial_write_u64(account.uid as u64);
    io::serial_write("\r\n  role           ");
    io::serial_write(account.role);
    io::serial_write("\r\n  local.console  ");
    io::serial_write(if account.local_console {
        "authorized"
    } else {
        "denied"
    });
    io::serial_write("\r\n");
}

fn ssh_status() {
    io::serial_write("\r\n\x1b[1;36mSecure shell status\x1b[0m\r\n");
    io::serial_write("  service          enabled\r\n");
    io::serial_write("  transport        native TCP/IPv4\r\n");
    io::serial_write("  protocol         SSHv2\r\n");
    io::serial_write("  authentication   Ed25519 public key only\r\n");
    io::serial_write("  password login   disabled\r\n");
    io::serial_write("  root login       disabled\r\n");
    io::serial_write("  account          admin (uid 1000)\r\n");
    io::serial_write("  listen           ");
    io::serial_write(if network::ssh_listening() {
        "0.0.0.0:22"
    } else {
        "waiting for DHCP"
    });
    io::serial_write("\r\n\r\n");
}

fn decimal_width(mut value: u32) -> usize {
    let mut width = 1;
    while value >= 10 {
        value /= 10;
        width += 1;
    }
    width
}

fn status(
    frames: &FrameAllocator,
    heap: &KernelHeap,
    page_tables: &PageTables,
    boot_map: &BootMemoryMap,
) {
    let net = network::snapshot();
    io::serial_write("\r\n\x1b[1;36mSystem status\x1b[0m\r\n");
    io::serial_write("  kernel       ready\r\n");
    io::serial_write("  userspace    init completed, exit=");
    io::serial_write_u64(userspace::exit_code());
    io::serial_write("\r\n  scheduler    preemptions=");
    io::serial_write_u64(arch::user_preemptions());
    io::serial_write("\r\n  memory free  ");
    io::serial_write_u64(frames.free_pages().saturating_mul(PAGE_SIZE) / (1024 * 1024));
    io::serial_write(" MiB\r\n  heap free    ");
    io::serial_write_u64(heap.free() as u64);
    io::serial_write(" bytes\r\n  fw conventional pages  ");
    io::serial_write_u64(boot_map.conventional_pages);
    io::serial_write("\r\n  fw reclaimable pages   ");
    io::serial_write_u64(boot_map.reclaimable_pages);
    io::serial_write("\r\n  fw runtime pages       ");
    io::serial_write_u64(boot_map.runtime_pages);
    io::serial_write("\r\n  page tables  cr3=");
    io::serial_write_hex(page_tables.root_phys());
    io::serial_write("\r\n  capability   mailbox verified\r\n");
    io::serial_write("  identity     system (uid 0)\r\n");
    io::serial_write("  network      ");
    io::serial_write(if network::configured() {
        "DHCP bound"
    } else {
        "offline"
    });
    io::serial_write("\r\n  IPv4         ");
    write_ip(net.ipv4);
    io::serial_write("\r\n  SSH          ");
    io::serial_write(if network::ssh_listening() {
        "listening on tcp/22"
    } else {
        "waiting for DHCP"
    });
    io::serial_write("\r\n  AI runtime   not installed");
    io::serial_write("\r\n\r\n");
}

fn debug(
    frames: &FrameAllocator,
    heap: &KernelHeap,
    page_tables: &PageTables,
    boot_map: &BootMemoryMap,
) {
    let net = network::snapshot();
    io::serial_write("\r\n\x1b[1;36mDebug snapshot\x1b[0m\r\n");
    io::serial_write("  cpu.mode          x86_64 long mode\r\n");
    io::serial_write("  firmware          UEFI services detached\r\n");
    io::serial_write("  privilege.kernel  CPL0\r\n");
    io::serial_write("  privilege.user    CPL3 verified\r\n");
    io::serial_write("  paging.cr3        ");
    io::serial_write_hex(page_tables.root_phys());
    io::serial_write("\r\n  paging.user_base  ");
    io::serial_write_hex(userspace::USER_CODE_VA);
    io::serial_write("\r\n  memory.regions    ");
    io::serial_write_u64(frames.region_count() as u64);
    io::serial_write("\r\n  memory.free_mib   ");
    io::serial_write_u64(frames.free_pages().saturating_mul(PAGE_SIZE) / (1024 * 1024));
    io::serial_write("\r\n  heap.used_bytes   ");
    io::serial_write_u64(heap.used() as u64);
    io::serial_write("\r\n  heap.free_bytes   ");
    io::serial_write_u64(heap.free() as u64);
    io::serial_write("\r\n  firmware.maps     ");
    io::serial_write_u64(boot_map.descriptors as u64);
    io::serial_write(" descriptors\r\n");
    io::serial_write("  interrupts        32 exception vectors\r\n");
    io::serial_write("  timer.hz          ");
    io::serial_write_u64(arch::TIMER_HZ);
    io::serial_write("\r\n  timer.ticks       ");
    io::serial_write_u64(arch::timer_ticks());
    io::serial_write("\r\n  syscall           int 0x80\r\n");
    io::serial_write("  init.exit         ");
    io::serial_write_u64(userspace::exit_code());
    io::serial_write("\r\n  init.preemptions  ");
    io::serial_write_u64(arch::user_preemptions());
    io::serial_write("\r\n  ipc.handle        0x1001\r\n");
    io::serial_write("  ipc.last_value    ");
    io::serial_write_u64(userspace::mailbox_state().1);
    io::serial_write("\r\n  network.driver    ");
    io::serial_write(if net.device { "RTL8139" } else { "none" });
    io::serial_write("\r\n  network.link      ");
    io::serial_write(if net.link { "up" } else { "down" });
    io::serial_write("\r\n  network.dhcp      ");
    io::serial_write(dhcp_name(net.dhcp));
    io::serial_write("\r\n  network.ipv4      ");
    write_ip(net.ipv4);
    io::serial_write("\r\n  network.dns       ");
    write_ip(net.dns);
    io::serial_write("\r\n  network.rx        ");
    io::serial_write_u64(net.rx_packets);
    io::serial_write(" packets\r\n  network.tx        ");
    io::serial_write_u64(net.tx_packets);
    io::serial_write(" packets\r\n  network.dropped   ");
    io::serial_write_u64(net.dropped);
    io::serial_write("\r\n\r\n");
}

fn network_status() {
    let state = network::snapshot();
    io::serial_write("\r\n\x1b[1;36mNetwork status\x1b[0m\r\n");
    io::serial_write("  driver             ");
    io::serial_write(if state.device { "RTL8139" } else { "not found" });
    io::serial_write("\r\n  link               ");
    io::serial_write(if state.link { "up" } else { "down" });
    io::serial_write("\r\n  pci.location       ");
    io::serial_write_u64(state.pci_bus as u64);
    io::serial_write(":");
    io::serial_write_u64(state.pci_device as u64);
    io::serial_write(".0\r\n  io.base            ");
    io::serial_write_hex(state.io_base as u64);
    io::serial_write("\r\n  mac                ");
    write_mac(state.mac);
    io::serial_write("\r\n  dhcp.state         ");
    io::serial_write(dhcp_name(state.dhcp));
    io::serial_write("\r\n  dhcp.server        ");
    write_ip(state.dhcp_server);
    io::serial_write("\r\n  dhcp.lease.seconds ");
    io::serial_write_u64(state.lease_seconds as u64);
    io::serial_write("\r\n  ipv4.address       ");
    write_ip(state.ipv4);
    io::serial_write("\r\n  ipv4.netmask       ");
    write_ip(state.netmask);
    io::serial_write("\r\n  ipv4.gateway       ");
    write_ip(state.gateway);
    io::serial_write("\r\n  ipv4.dns           ");
    write_ip(state.dns);
    io::serial_write("\r\n  icmp.echo          ");
    io::serial_write(if network::configured() {
        "active"
    } else {
        "inactive"
    });
    io::serial_write("\r\n  ssh.service        ");
    io::serial_write(if network::ssh_listening() {
        "listening on tcp/22"
    } else {
        "waiting for DHCP"
    });
    io::serial_write("\r\n");
    io::serial_write("\r\n\x1b[1;36mPacket counters\x1b[0m\r\n");
    write_counter("rx.packets", state.rx_packets);
    write_counter("rx.bytes", state.rx_bytes);
    write_counter("tx.packets", state.tx_packets);
    write_counter("tx.bytes", state.tx_bytes);
    write_counter("arp.request.rx", state.arp_requests);
    write_counter("arp.reply.tx", state.arp_replies);
    write_counter("arp.query.tx", state.arp_queries);
    write_counter("arp.response.rx", state.arp_responses);
    write_counter("icmp.echo.rx", state.icmp_requests);
    write_counter("icmp.echo.tx", state.icmp_replies);
    write_counter("ping.reply.rx", state.ping_replies);
    write_counter("dns.query.tx", state.dns_queries);
    write_counter("dns.reply.rx", state.dns_replies);
    write_counter("dropped", state.dropped);
    io::serial_write("\r\n");
}

fn ip_status() {
    let state = network::snapshot();
    io::serial_write("\r\n\x1b[1;36mIPv4 configuration\x1b[0m\r\n");
    io::serial_write("  interface  net0\r\n");
    io::serial_write("  state      ");
    io::serial_write(if state.link { "UP" } else { "DOWN" });
    io::serial_write("\r\n  address    ");
    write_ip(state.ipv4);
    io::serial_write("\r\n  netmask    ");
    write_ip(state.netmask);
    io::serial_write("\r\n  gateway    ");
    write_ip(state.gateway);
    io::serial_write("\r\n  dns        ");
    write_ip(state.dns);
    io::serial_write("\r\n  mac        ");
    write_mac(state.mac);
    io::serial_write("\r\n  source     DHCP (state: ");
    io::serial_write(dhcp_name(state.dhcp));
    io::serial_write(")\r\n\r\n");
}

fn ping_target(target: &[u8]) {
    io::serial_write("ping: target=");
    if target.is_empty() {
        write_ip(network::snapshot().gateway);
    } else {
        io::serial_write_bytes(target);
    }
    io::serial_write(" bytes=24\r\n");
    match network::ping(target) {
        Ok(result) => {
            io::serial_write("resolved: ");
            write_ip(result.address);
            io::serial_write("\r\n");
            io::serial_write("reply: source=");
            write_ip(result.address);
            io::serial_write(" time_ms=");
            io::serial_write_u64(result.milliseconds);
            io::serial_write(" status=ok\r\n");
        }
        Err(error) => {
            io::serial_write("error: ");
            io::serial_write(match error {
                PingError::NetworkUnavailable => "network unavailable",
                PingError::InvalidName => "invalid host name or address",
                PingError::DnsTimeout => "DNS lookup failed",
                PingError::NeighborTimeout => "ARP resolution failed",
                PingError::EchoTimeout => "no ICMP echo reply",
            });
            io::serial_write("\r\n");
        }
    }
}

fn dhcp_name(state: DhcpState) -> &'static str {
    match state {
        DhcpState::Disabled => "disabled",
        DhcpState::Discovering => "discovering",
        DhcpState::Requesting => "requesting",
        DhcpState::Bound => "bound",
        DhcpState::TimedOut => "timed out",
    }
}

fn write_ip(address: [u8; 4]) {
    for (index, octet) in address.iter().enumerate() {
        if index != 0 {
            io::serial_write_byte(b'.');
        }
        io::serial_write_u64(*octet as u64);
    }
}

fn write_mac(address: [u8; 6]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, octet) in address.iter().enumerate() {
        if index != 0 {
            io::serial_write_byte(b':');
        }
        io::serial_write_byte(HEX[(octet >> 4) as usize]);
        io::serial_write_byte(HEX[(octet & 0x0f) as usize]);
    }
}

fn write_counter(label: &str, value: u64) {
    io::serial_write("  ");
    io::serial_write(label);
    let padding = 19usize.saturating_sub(label.len());
    for _ in 0..padding {
        io::serial_write_byte(b' ');
    }
    io::serial_write_u64(value);
    io::serial_write("\r\n");
}
