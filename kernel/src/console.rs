use crate::arch;
use crate::io::{self, KeyboardState};
use crate::memory::{FrameAllocator, KernelHeap, PageTables, PAGE_SIZE};
use crate::userspace;

pub fn run(frames: &mut FrameAllocator, heap: &mut KernelHeap, page_tables: &PageTables) -> ! {
    io::serial_write("\r\nORYVAEL OS native base\r\n");
    io::serial_write("bare-metal x86_64 | ring3 init | capability syscall boundary\r\n");
    io::serial_write("type 'help' for commands\r\n\r\n");

    let mut keyboard = KeyboardState::new();
    let mut line = [0u8; 128];
    let mut length = 0usize;
    let mut last_was_cr = false;
    prompt();

    loop {
        let byte = io::serial_try_read().or_else(|| keyboard.try_read_ascii());
        match byte {
            Some(b'\r') => {
                io::serial_write("\r\n");
                execute(&line[..length], frames, heap, page_tables);
                length = 0;
                last_was_cr = true;
                prompt();
            }
            Some(b'\n') if last_was_cr => last_was_cr = false,
            Some(b'\n') => {
                io::serial_write("\r\n");
                execute(&line[..length], frames, heap, page_tables);
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
) {
    let command = trim_ascii(line);
    if command.is_empty() {
        return;
    }

    match command {
        b"help" => io::serial_write(
            "commands: help mem uptime alloc vm ps fs ipc clear about reboot\r\n",
        ),
        b"mem" => {
            io::serial_write("memory: conventional_free_pages=");
            io::serial_write_u64(frames.free_pages());
            io::serial_write(" free_mib=");
            io::serial_write_u64(frames.free_pages().saturating_mul(PAGE_SIZE) / (1024 * 1024));
            io::serial_write(" heap_used=");
            io::serial_write_u64(heap.used() as u64);
            io::serial_write(" heap_free=");
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
            io::serial_write("vm: oryvael_cr3=");
            io::serial_write_hex(page_tables.root_phys());
            io::serial_write(" user_base=");
            io::serial_write_hex(userspace::USER_CODE_VA);
            io::serial_write("\r\n");
        }
        b"ps" => {
            io::serial_write("process: init state=exited code=");
            io::serial_write_u64(userspace::exit_code());
            io::serial_write(" ring3_preemptions=");
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
        b"about" => io::serial_write(
            "ORYVAEL native OS base: own CR3, exceptions, ring3, syscalls, capability IPC, ramfs\r\n",
        ),
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
    io::serial_write("oryvael> ");
}
