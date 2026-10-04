use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::{c_int, c_short};
use std::os::unix::net::UnixStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug)]
pub struct PeerProcess {
    credentials: PeerCredentials,
    pidfd: OwnedFd,
}

impl PeerProcess {
    pub fn credentials(&self) -> PeerCredentials {
        self.credentials
    }

    pub fn ensure_alive(&self) -> io::Result<()> {
        pidfd_ensure_alive(&self.pidfd)
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxUCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxPollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn getsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *mut c_void,
        option_len: *mut u32,
    ) -> c_int;

    fn poll(fds: *mut LinuxPollFd, nfds: usize, timeout: c_int) -> c_int;
}

#[cfg(target_os = "linux")]
const SOL_SOCKET: c_int = 1;
#[cfg(target_os = "linux")]
const SO_PEERCRED: c_int = 17;
#[cfg(target_os = "linux")]
const SO_PEERPIDFD: c_int = 77;
#[cfg(target_os = "linux")]
const POLLIN: c_short = 0x0001;

#[cfg(target_os = "linux")]
pub fn peer_process(stream: &UnixStream) -> io::Result<PeerProcess> {
    let credentials = peer_credentials(stream)?;
    let pidfd = peer_pidfd(stream)?;
    let process = PeerProcess { credentials, pidfd };
    process.ensure_alive()?;
    Ok(process)
}

#[cfg(target_os = "linux")]
pub fn peer_credentials(stream: &UnixStream) -> io::Result<PeerCredentials> {
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

#[cfg(target_os = "linux")]
fn peer_pidfd(stream: &UnixStream) -> io::Result<OwnedFd> {
    let mut raw_pidfd: c_int = -1;
    let mut length = size_of::<c_int>() as u32;
    let result = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut raw_pidfd as *mut c_int).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!(
                "SO_PEERPIDFD is required for trusted IPC peer pinning: {error}"
            ),
        ));
    }
    if length as usize != size_of::<c_int>() || raw_pidfd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SO_PEERPIDFD returned invalid descriptor {raw_pidfd} with length {length}"
            ),
        ));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(raw_pidfd) })
}

#[cfg(target_os = "linux")]
fn pidfd_ensure_alive(pidfd: &OwnedFd) -> io::Result<()> {
    loop {
        let mut pollfd = LinuxPollFd {
            fd: pidfd.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        let result = unsafe { poll(&mut pollfd, 1, 0) };
        if result == 0 {
            return Ok(());
        }
        if result > 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!(
                    "peer process exited while trusted identity was being evaluated (pidfd revents=0x{:x})",
                    pollfd.revents
                ),
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn peer_process(_stream: &UnixStream) -> io::Result<PeerProcess> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ORYVAEL peer authentication requires Linux SO_PEERCRED and SO_PEERPIDFD",
    ))
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

    #[test]
    fn unix_pair_returns_live_kernel_peer_pidfd() {
        let (left, _right) = UnixStream::pair().expect("pair");
        let process = peer_process(&left).expect("peer process");
        assert_eq!(process.credentials().pid as u32, std::process::id());
        process.ensure_alive().expect("live pidfd");
    }
}
