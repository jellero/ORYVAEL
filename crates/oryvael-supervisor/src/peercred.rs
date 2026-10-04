use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::raw::c_int;
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(target_os = "linux")]
pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
    #[repr(C)]
    struct LinuxUCred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    unsafe extern "C" {
        fn getsockopt(
            socket: c_int,
            level: c_int,
            option_name: c_int,
            option_value: *mut c_void,
            option_len: *mut u32,
        ) -> c_int;
    }

    const SOL_SOCKET: c_int = 1;
    const SO_PEERCRED: c_int = 17;

    let mut raw = LinuxUCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = size_of::<LinuxUCred>() as u32;
    let result = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut raw as *mut LinuxUCred).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<LinuxUCred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SO_PEERCRED returned {} bytes, expected {}",
                length,
                size_of::<LinuxUCred>()
            ),
        ));
    }
    if raw.pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SO_PEERCRED returned invalid pid {}", raw.pid),
        ));
    }

    Ok(PeerCredentials {
        pid: raw.pid,
        uid: raw.uid,
        gid: raw.gid,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn peer_credentials(_stream: &UnixStream) -> io::Result<PeerCredentials> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ORYVAEL peer authentication currently requires Linux SO_PEERCRED",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn unix_pair_reports_current_process_pid() {
        let (left, _right) = UnixStream::pair().expect("pair");
        let credentials = peer_credentials(&left).expect("peer credentials");
        assert_eq!(credentials.pid as u32, std::process::id());
    }
}
