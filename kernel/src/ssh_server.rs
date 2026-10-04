use core::future::poll_fn;
use core::task::Poll;

use embedded_io_async::{Error, ErrorKind, ErrorType, Read, Write};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zssh::ed25519_dalek::{SigningKey, VerifyingKey};
use zssh::{AuthMethod, Behavior, PublicKey, Request, SecretKey, Transport};

use crate::{arch, io, network};

const HOST_SECRET_KEY: [u8; 32] = [
    0x9b, 0xd8, 0x6c, 0xab, 0x70, 0x28, 0xc6, 0x53, 0xf4, 0x17, 0x57, 0x61, 0x52, 0xdb, 0x16, 0x19,
    0x56, 0x3f, 0x9c, 0x3c, 0xfc, 0x72, 0x89, 0x9e, 0x8a, 0x34, 0xb9, 0xcf, 0x7f, 0x85, 0x5d, 0x9f,
];

const ADMIN_PUBLIC_KEY: [u8; 32] = [
    0x65, 0x6a, 0xac, 0xa0, 0x50, 0xc1, 0x29, 0xa0, 0x26, 0x74, 0xd1, 0xfa, 0x10, 0xfd, 0x22, 0x60,
    0x1f, 0x90, 0xc9, 0xda, 0xd3, 0xf8, 0x5b, 0x96, 0x56, 0x07, 0xed, 0xab, 0x6a, 0xcf, 0x83, 0x66,
];

#[derive(Clone, Copy, Debug)]
pub struct NetworkError;

impl Error for NetworkError {
    fn kind(&self) -> ErrorKind {
        ErrorKind::ConnectionAborted
    }
}

#[derive(Debug)]
struct NetworkStream;

impl ErrorType for NetworkStream {
    type Error = NetworkError;
}

impl Read for NetworkStream {
    async fn read(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
        poll_fn(|context| {
            network::poll();
            let count = network::tcp_read(output);
            if count != 0 {
                Poll::Ready(Ok(count))
            } else if !network::tcp_connected() {
                Poll::Ready(Ok(0))
            } else {
                context.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await
    }
}

impl Write for NetworkStream {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Self::Error> {
        if network::tcp_write(bytes) {
            Ok(bytes.len())
        } else {
            Err(NetworkError)
        }
    }
}

struct OryvaelBehavior {
    stream: NetworkStream,
    random: ChaCha20Rng,
    host_key: SecretKey,
    admin_key: PublicKey,
}

#[derive(Clone, Copy, Debug)]
enum Command {
    Help,
    WhoAmI,
    Ip,
    Uptime,
    Reboot,
    Invalid,
}

impl Behavior for OryvaelBehavior {
    type Stream = NetworkStream;

    fn stream(&mut self) -> &mut Self::Stream {
        &mut self.stream
    }

    type Random = ChaCha20Rng;

    fn random(&mut self) -> &mut Self::Random {
        &mut self.random
    }

    fn host_secret_key(&self) -> &SecretKey {
        &self.host_key
    }

    fn server_id(&self) -> &'static str {
        "SSH-2.0-ORYVAEL_0.0.2"
    }

    type User = &'static str;

    fn allow_user(&mut self, username: &str, method: &AuthMethod) -> Option<Self::User> {
        match method {
            AuthMethod::PublicKey(key) if username == "admin" && *key == self.admin_key => {
                Some("admin")
            }
            _ => None,
        }
    }

    fn allow_shell(&self) -> bool {
        true
    }

    type Command = Command;

    fn parse_command(&mut self, command: &str) -> Self::Command {
        parse_command(command.as_bytes())
    }
}

pub async fn run() {
    loop {
        poll_fn(|context| {
            network::poll();
            if network::tcp_connected() {
                Poll::Ready(())
            } else {
                context.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        io::serial_write("\r\nSSH: TCP connection accepted\r\n");
        let _ = serve_connection().await;
        io::serial_write("SSH: session closed\r\n");
        network::tcp_reset();
    }
}

async fn serve_connection() -> Result<(), zssh::Error<NetworkError>> {
    let admin_key =
        VerifyingKey::from_bytes(&ADMIN_PUBLIC_KEY).map_err(|_| zssh::Error::IO(NetworkError))?;
    let mut seed = HOST_SECRET_KEY;
    let ticks = arch::timer_ticks().to_le_bytes();
    for (index, byte) in ticks.iter().enumerate() {
        seed[index] ^= *byte;
    }
    let behavior = OryvaelBehavior {
        stream: NetworkStream,
        random: ChaCha20Rng::from_seed(seed),
        host_key: SecretKey::Ed25519 {
            secret_key: SigningKey::from_bytes(&HOST_SECRET_KEY),
        },
        admin_key: PublicKey::Ed25519 {
            public_key: admin_key,
        },
    };
    let mut packet_buffer = [0u8; 8192];
    let mut transport = Transport::new(&mut packet_buffer, behavior);
    loop {
        let mut channel = transport.accept().await?;
        match channel.request() {
            Request::Shell => {
                interactive_shell(&mut channel).await?;
                channel.exit(0).await?;
            }
            Request::Exec(command) => {
                run_command(&mut channel, command).await?;
                channel.exit(0).await?;
            }
        }
    }
}

async fn interactive_shell(
    channel: &mut zssh::Channel<'_, '_, OryvaelBehavior>,
) -> Result<(), zssh::Error<NetworkError>> {
    channel
        .write_all_stdout(b"\r\nWelcome to ORYVAEL secure shell\r\nAuthenticated as admin (uid 1000)\r\nType 'help' for commands.\r\n\r\noryvael::admin> ")
        .await?;
    let mut line = [0u8; 128];
    let mut length = 0usize;
    loop {
        let mut byte = [0u8; 1];
        if channel.read_exact_stdin(&mut byte).await? == 0 {
            return Ok(());
        }
        match byte[0] {
            b'\r' | b'\n' => {
                channel.write_all_stdout(b"\r\n").await?;
                if &line[..length] == b"exit" || &line[..length] == b"logout" {
                    channel.write_all_stdout(b"logout\r\n").await?;
                    return Ok(());
                }
                run_command(channel, parse_command(&line[..length])).await?;
                length = 0;
                channel.write_all_stdout(b"oryvael::admin> ").await?;
            }
            0x08 | 0x7f if length != 0 => {
                length -= 1;
                channel.write_all_stdout(b"\x08 \x08").await?;
            }
            value if (0x20..=0x7e).contains(&value) && length < line.len() => {
                line[length] = value;
                length += 1;
                channel.write_all_stdout(&[value]).await?;
            }
            _ => {}
        }
    }
}

async fn run_command(
    channel: &mut zssh::Channel<'_, '_, OryvaelBehavior>,
    command: Command,
) -> Result<(), zssh::Error<NetworkError>> {
    match command {
        Command::Help => channel.write_all_stdout(
            b"help     show commands\r\nwhoami   active identity\r\nip       DHCP address\r\nuptime   kernel uptime\r\nreboot   restart ORYVAEL\r\nexit     close session\r\n",
        ).await?,
        Command::WhoAmI => channel
            .write_all_stdout(b"admin uid=1000 role=human-administrator auth=ed25519\r\n")
            .await?,
        Command::Ip => {
            let address = network::snapshot().ipv4;
            let mut output = [0u8; 48];
            let mut length = 0;
            length += append(&mut output[length..], b"net0 ");
            for (index, octet) in address.iter().enumerate() {
                if index != 0 {
                    output[length] = b'.';
                    length += 1;
                }
                length += append_decimal(&mut output[length..], *octet as u64);
            }
            length += append(&mut output[length..], b" dhcp\r\n");
            channel.write_all_stdout(&output[..length]).await?;
        }
        Command::Uptime => {
            let mut output = [0u8; 48];
            let mut length = append(&mut output, b"uptime ");
            length += append_decimal(
                &mut output[length..],
                arch::timer_ticks() / arch::TIMER_HZ,
            );
            length += append(&mut output[length..], b" seconds\r\n");
            channel.write_all_stdout(&output[..length]).await?;
        }
        Command::Reboot => {
            channel.write_all_stdout(b"rebooting...\r\n").await?;
            io::reboot();
        }
        Command::Invalid => channel
            .write_all_stderr(b"unknown command; type 'help'\r\n")
            .await?,
    }
    Ok(())
}

fn parse_command(input: &[u8]) -> Command {
    match trim(input) {
        b"help" => Command::Help,
        b"whoami" => Command::WhoAmI,
        b"ip" | b"ip -a" => Command::Ip,
        b"uptime" => Command::Uptime,
        b"reboot" => Command::Reboot,
        _ => Command::Invalid,
    }
}

fn trim(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

fn append(output: &mut [u8], value: &[u8]) -> usize {
    let count = output.len().min(value.len());
    output[..count].copy_from_slice(&value[..count]);
    count
}

fn append_decimal(output: &mut [u8], mut value: u64) -> usize {
    let mut reversed = [0u8; 20];
    let mut count = 0;
    loop {
        reversed[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for index in 0..count {
        output[index] = reversed[count - index - 1];
    }
    count
}
