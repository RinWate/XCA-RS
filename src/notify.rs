//! Central toast wording for data mutations: every action reports what
//! it touched and where — the database, ~/.ssh files or ~/.ssh/config.
//! Building the phrases in one place keeps them uniform and makes the
//! wording a single edit away.

use crate::tr;

/// "~/.ssh/a, ~/.ssh/b" — the storage prefix for file lists.
fn ssh_paths(files: &[String]) -> String {
    files
        .iter()
        .map(|f| format!("~/.ssh/{f}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn deleted_db() -> String {
    tr!("Deleted")
}

pub fn deleted_ssh_files(files: &[String]) -> String {
    tr!("Deleted: %{list}", list = ssh_paths(files))
}

pub fn deleted_host(name: &str) -> String {
    tr!("Host %{name} deleted", name = name)
}

pub fn renamed_db() -> String {
    tr!("Renamed")
}

pub fn renamed_ssh_files(files: &[String]) -> String {
    tr!("Renamed to %{list}", list = files.join(", "))
}

pub fn key_imported_db(name: &str) -> String {
    tr!("Key “%{name}” imported into the database", name = name)
}

pub fn cert_imported_db(name: &str) -> String {
    tr!("Certificate “%{name}” imported into the database", name = name)
}

pub fn key_written_ssh(name: &str) -> String {
    tr!("SSH key %{name} written to ~/.ssh", name = name)
}

pub fn cert_written_ssh(name: &str) -> String {
    tr!("SSH certificate %{name} written to ~/.ssh", name = name)
}

pub fn host_saved(name: &str) -> String {
    tr!("Host %{name} saved", name = name)
}

pub fn host_added(name: &str) -> String {
    tr!("Host %{name} added", name = name)
}
