#[derive(Clone, Copy)]
pub struct Account {
    pub name: &'static str,
    pub uid: u32,
    pub role: &'static str,
    pub local_console: bool,
    pub ssh_login: bool,
}

// Accounts are explicit kernel identities. Remote access is restricted to the
// separately provisioned admin Ed25519 key; system/root cannot log in remotely.
const ACCOUNTS: [Account; 2] = [
    Account {
        name: "system",
        uid: 0,
        role: "kernel-console",
        local_console: true,
        ssh_login: false,
    },
    Account {
        name: "admin",
        uid: 1000,
        role: "human-administrator",
        local_console: false,
        ssh_login: true,
    },
];

pub fn all() -> &'static [Account] {
    &ACCOUNTS
}

pub fn current() -> Account {
    ACCOUNTS[0]
}
