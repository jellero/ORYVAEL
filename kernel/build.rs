use std::env;
use std::fs;
use std::path::PathBuf;

const DEFAULT_ADMIN_PUBLIC_KEY: [u8; 32] = [
    0x65, 0x6a, 0xac, 0xa0, 0x50, 0xc1, 0x29, 0xa0, 0x26, 0x74, 0xd1, 0xfa, 0x10, 0xfd, 0x22, 0x60,
    0x1f, 0x90, 0xc9, 0xda, 0xd3, 0xf8, 0x5b, 0x96, 0x56, 0x07, 0xed, 0xab, 0x6a, 0xcf, 0x83, 0x66,
];

fn main() {
    println!("cargo:rerun-if-env-changed=ORYVAEL_ADMIN_PUBKEY_FILE");

    let key = match env::var_os("ORYVAEL_ADMIN_PUBKEY_FILE") {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            let text = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "failed to read ORYVAEL admin public key {}: {error}",
                    path.display()
                )
            });
            parse_openssh_ed25519(&text).unwrap_or_else(|error| {
                panic!(
                    "invalid ORYVAEL admin public key {}: {error}",
                    path.display()
                )
            })
        }
        None => DEFAULT_ADMIN_PUBLIC_KEY,
    };

    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"))
        .join("admin_public_key.rs");
    let mut source = String::from("pub const ADMIN_PUBLIC_KEY: [u8; 32] = [\n    ");
    for (index, byte) in key.iter().enumerate() {
        if index != 0 {
            if index % 8 == 0 {
                source.push_str("\n    ");
            } else {
                source.push(' ');
            }
        }
        source.push_str(&format!("0x{byte:02x},"));
    }
    source.push_str("\n];\n");
    fs::write(output, source).expect("write generated admin public key");
}

fn parse_openssh_ed25519(text: &str) -> Result<[u8; 32], &'static str> {
    let mut fields = text.split_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        return Err("expected an ssh-ed25519 OpenSSH public key");
    }
    let encoded = fields.next().ok_or("missing base64 public-key payload")?;
    let blob = decode_base64(encoded)?;
    let mut offset = 0usize;
    let key_type = read_ssh_string(&blob, &mut offset)?;
    if key_type != b"ssh-ed25519" {
        return Err("OpenSSH payload is not ssh-ed25519");
    }
    let raw_key = read_ssh_string(&blob, &mut offset)?;
    if raw_key.len() != 32 || offset != blob.len() {
        return Err("Ed25519 public key must contain exactly 32 raw bytes");
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(raw_key);
    Ok(key)
}

fn read_ssh_string<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8], &'static str> {
    if bytes.len().saturating_sub(*offset) < 4 {
        return Err("truncated SSH key payload");
    }
    let length = u32::from_be_bytes([
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ]) as usize;
    *offset += 4;
    if bytes.len().saturating_sub(*offset) < length {
        return Err("truncated SSH string");
    }
    let value = &bytes[*offset..*offset + length];
    *offset += length;
    Ok(value)
}

fn decode_base64(input: &str) -> Result<Vec<u8>, &'static str> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut quartet = [0u8; 4];
    let mut count = 0usize;
    let mut saw_padding = false;

    for byte in input.bytes() {
        if saw_padding {
            return Err("base64 data appears after padding");
        }
        if byte == b'=' {
            quartet[count] = 64;
        } else {
            quartet[count] = base64_value(byte).ok_or("invalid base64 character")?;
        }
        count += 1;

        if count == 4 {
            if quartet[0] == 64 || quartet[1] == 64 {
                return Err("invalid base64 padding");
            }
            output.push((quartet[0] << 2) | (quartet[1] >> 4));
            if quartet[2] != 64 {
                output.push((quartet[1] << 4) | (quartet[2] >> 2));
                if quartet[3] != 64 {
                    output.push((quartet[2] << 6) | quartet[3]);
                } else {
                    saw_padding = true;
                }
            } else if quartet[3] == 64 {
                saw_padding = true;
            } else {
                return Err("invalid base64 padding");
            }
            count = 0;
        }
    }

    if count != 0 {
        return Err("base64 payload length is not a multiple of four");
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
