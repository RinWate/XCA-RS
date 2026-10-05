//! The user's `~/.ssh/config`: a faithful line-based model of the SSH
//! client configuration. `Host` blocks are parsed into editable entries;
//! everything else (global options, `Match` blocks, comments, blank
//! lines) is preserved verbatim, so a read-modify-write cycle only ever
//! reformats the blocks the user actually touched. One deliberate
//! normalization: line endings — a CRLF config is rewritten with LF
//! (ssh accepts both, LF is canonical here).

use crate::tr;

/// One line of a Host block: either an option (`key value`) or a raw
/// line (comment / blank) kept as written.
#[derive(Clone, Debug, PartialEq)]
pub enum Line {
    Option { key: String, value: String },
    Raw(String),
}

/// A `Host` stanza: the patterns and its lines in file order.
#[derive(Clone, Debug, Default)]
pub struct HostEntry {
    /// Everything after the `Host` keyword ("alias1 alias2", "*", "!old").
    pub patterns: String,
    pub lines: Vec<Line>,
}

impl HostEntry {
    /// The first pattern — the alias shown in lists.
    pub fn alias(&self) -> &str {
        self.patterns.split_whitespace().next().unwrap_or("")
    }

    /// First option value with this key (case-insensitive), if set.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.lines.iter().find_map(|l| match l {
            Line::Option { key: k, value } if k.eq_ignore_ascii_case(key) => {
                Some(value.as_str())
            }
            _ => None,
        })
    }

    /// Set an option: replace its first occurrence or append it.
    pub fn set(&mut self, key: &str, value: &str) {
        for l in self.lines.iter_mut() {
            if let Line::Option { key: k, value: v } = l
                && k.eq_ignore_ascii_case(key)
            {
                *v = value.to_string();
                return;
            }
        }
        self.lines.push(Line::Option {
            key: key.to_string(),
            value: value.to_string(),
        });
    }

    /// Drop every occurrence of an option (used when a field is cleared).
    pub fn remove(&mut self, key: &str) {
        self.lines
            .retain(|l| !matches!(l, Line::Option { key: k, .. } if k.eq_ignore_ascii_case(key)));
    }

    /// The option lines that are not covered by the editor's known
    /// fields, as `Key Value` text for the free-form editor.
    pub fn extra_options_text(&self, known: &[&str]) -> String {
        self.lines
            .iter()
            .filter_map(|l| match l {
                Line::Option { key, value }
                    if !known.iter().any(|k| key.eq_ignore_ascii_case(k)) =>
                {
                    Some(format!("{key} {value}"))
                }
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Replace everything except the known fields (and raw lines) with
    /// the free-form `Key Value` lines from the editor.
    pub fn set_extra_options(&mut self, known: &[&str], text: &str) {
        let mut kept: Vec<Line> = self
            .lines
            .iter()
            .filter(|l| match l {
                Line::Option { key, .. } => known.iter().any(|k| key.eq_ignore_ascii_case(k)),
                Line::Raw(_) => true,
            })
            .cloned()
            .collect();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.split_once(char::is_whitespace) {
                Some((key, value)) => kept.push(Line::Option {
                    key: key.to_string(),
                    value: value.trim().to_string(),
                }),
                None => kept.push(Line::Raw(line.to_string())),
            }
        }
        self.lines = kept;
    }
}

/// Everything the file consists of, in order.
#[derive(Clone, Debug, Default)]
pub enum Block {
    #[default]
    Empty,
    Host(HostEntry),
    /// Global options before the first block, `Match` stanzas, includes —
    /// preserved line by line.
    Raw(Vec<String>),
}

#[derive(Clone, Debug, Default)]
pub struct SshConfig {
    pub blocks: Vec<Block>,
}

/// Split an option line: `Key Value` or `Key=Value`.
fn split_option(line: &str) -> Option<(String, String)> {
    let (key, value) = if let Some((k, v)) = line.split_once('=') {
        (k, v)
    } else {
        line.split_once(char::is_whitespace)?
    };
    let key = key.trim();
    if key.is_empty() || key.starts_with('#') {
        return None;
    }
    Some((key.to_string(), value.trim().to_string()))
}

impl SshConfig {
    pub fn parse(text: &str) -> SshConfig {
        let mut cfg = SshConfig::default();
        for raw in text.lines() {
            let trimmed = raw.trim();
            let first = trimmed.split_whitespace().next().unwrap_or("");
            let (keyword, rest_is_eq) = if let Some((k, _)) = trimmed.split_once('=') {
                (k.trim().to_string(), true)
            } else {
                (first.to_string(), false)
            };
            let starts_block =
                keyword.eq_ignore_ascii_case("Host") || keyword.eq_ignore_ascii_case("Match");
            if starts_block {
                let patterns = if rest_is_eq {
                    trimmed
                        .split_once('=')
                        .map(|(_, v)| v.trim().to_string())
                        .unwrap_or_default()
                } else {
                    trimmed[first.len()..].trim().to_string()
                };
                if keyword.eq_ignore_ascii_case("Host") {
                    cfg.blocks.push(Block::Host(HostEntry {
                        patterns,
                        lines: Vec::new(),
                    }));
                } else {
                    cfg.blocks.push(Block::Raw(vec![raw.to_string()]));
                }
                continue;
            }
            match cfg.blocks.last_mut() {
                Some(Block::Host(entry)) => {
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        entry.lines.push(Line::Raw(raw.to_string()));
                    } else if let Some((key, value)) = split_option(trimmed) {
                        entry.lines.push(Line::Option { key, value });
                    } else {
                        entry.lines.push(Line::Raw(raw.to_string()));
                    }
                }
                block => {
                    let Some(raws) = (match block {
                        Some(Block::Raw(v)) => Some(v),
                        None => {
                            cfg.blocks.push(Block::Raw(Vec::new()));
                            match cfg.blocks.last_mut() {
                                Some(Block::Raw(v)) => Some(v),
                                _ => None,
                            }
                        }
                        _ => None,
                    }) else {
                        continue;
                    };
                    raws.push(raw.to_string());
                }
            }
        }
        cfg
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for (i, block) in self.blocks.iter().enumerate() {
            match block {
                Block::Empty => {}
                Block::Host(entry) => {
                    if i > 0 && !out.is_empty() && !out.ends_with("\n\n") {
                        out.push('\n');
                    }
                    out.push_str(&format!("Host {}\n", entry.patterns));
                    for line in &entry.lines {
                        match line {
                            Line::Option { key, value } => {
                                out.push_str(&format!("    {key} {value}\n"));
                            }
                            Line::Raw(raw) => {
                                out.push_str(raw);
                                out.push('\n');
                            }
                        }
                    }
                }
                Block::Raw(lines) => {
                    for raw in lines {
                        out.push_str(raw);
                        out.push('\n');
                    }
                }
            }
        }
        out
    }

    /// Indexes of the Host blocks, in file order.
    pub fn host_block_ids(&self) -> Vec<usize> {
        self.blocks
            .iter()
            .enumerate()
            .filter_map(|(i, b)| matches!(b, Block::Host(_)).then_some(i))
            .collect()
    }

    pub fn host(&self, block_id: usize) -> Option<&HostEntry> {
        match self.blocks.get(block_id) {
            Some(Block::Host(e)) => Some(e),
            _ => None,
        }
    }

    pub fn host_mut(&mut self, block_id: usize) -> Option<&mut HostEntry> {
        match self.blocks.get_mut(block_id) {
            Some(Block::Host(e)) => Some(e),
            _ => None,
        }
    }
}

// ---- file access ----

pub fn config_path() -> std::path::PathBuf {
    let home = std::env::var_os("HOME").unwrap_or_default();
    std::path::Path::new(&home).join(".ssh").join("config")
}

/// Parse the user's config; a missing file is an empty config.
pub fn load() -> SshConfig {
    match std::fs::read_to_string(config_path()) {
        Ok(text) => SshConfig::parse(&text),
        Err(_) => SshConfig::default(),
    }
}

/// Write the config back (0600, ~/.ssh created with 0700 when missing).
pub fn save(cfg: &SshConfig) -> Result<(), String> {
    save_at(&config_path(), cfg)
}

/// The path-explicit variant of [`save`].
pub fn save_at(path: &std::path::Path, cfg: &SshConfig) -> Result<(), String> {
    let dir = path.parent().unwrap_or(path);
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("{}: {e}", tr!("Cannot write to ~/.ssh")))?;
    std::fs::write(path, cfg.to_text())
        .map_err(|e| format!("{}: {e}", tr!("Cannot write to ~/.ssh")))?;
    // chmod after the write: on first save the file does not exist yet.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# global comment
ServerAliveInterval 60

Host gw jump
    # the gateway
    HostName gw.example.com
    User admin
    Port=2222
    IdentityFile ~/.ssh/id_ed25519

Match host *.internal
    ProxyJump gw

Host *
    ForwardAgent yes
";

    #[test]
    fn parse_and_rewrite_faithfully() {
        let cfg = SshConfig::parse(SAMPLE);
        let ids = cfg.host_block_ids();
        assert_eq!(ids.len(), 2);

        let gw = cfg.host(ids[0]).unwrap();
        assert_eq!(gw.alias(), "gw");
        assert_eq!(gw.patterns, "gw jump");
        assert_eq!(gw.get("HostName"), Some("gw.example.com"));
        assert_eq!(gw.get("Port"), Some("2222")); // Key=Value syntax
        assert_eq!(gw.get("identityfile"), Some("~/.ssh/id_ed25519"));
        // comment line kept
        assert!(gw.lines.iter().any(|l| matches!(l, Line::Raw(r) if r.contains("gateway"))));

        // Match block and global options survive as raw blocks.
        let text = cfg.to_text();
        let reparsed = SshConfig::parse(&text);
        assert_eq!(reparsed.host_block_ids().len(), 2);
        let gw2 = reparsed.host(reparsed.host_block_ids()[0]).unwrap();
        assert_eq!(gw2.get("Port"), Some("2222"));
        assert!(text.contains("ServerAliveInterval 60"));
        assert!(text.contains("Match host *.internal"));
        assert!(text.contains("ProxyJump gw"));
        // and rewriting again does not change anything
        assert_eq!(reparsed.to_text(), text);
    }

    #[test]
    fn edit_set_remove_and_extras() {
        let mut cfg = SshConfig::parse(SAMPLE);
        let id = cfg.host_block_ids()[0];
        let gw = cfg.host_mut(id).unwrap();
        gw.set("User", "root");
        gw.set("ProxyJump", "bastion");
        gw.remove("Port");
        assert_eq!(gw.get("User"), Some("root"));
        assert_eq!(gw.get("ProxyJump"), Some("bastion"));
        assert_eq!(gw.get("Port"), None);

        let known = ["HostName", "User", "Port", "IdentityFile", "CertificateFile", "ProxyJump"];
        let extras = gw.extra_options_text(&known);
        assert!(extras.is_empty(), "no extras in the sample: {extras}");
        gw.set_extra_options(&known, "Compression yes\nAddKeysToAgent ask");
        assert_eq!(gw.get("Compression"), Some("yes"));
        assert_eq!(gw.get("AddKeysToAgent"), Some("ask"));
        assert_eq!(gw.get("User"), Some("root"));
        // known fields survive set_extra_options, raw comments too
        assert!(gw.lines.iter().any(|l| matches!(l, Line::Raw(r) if r.contains("gateway"))));
        gw.set_extra_options(&known, "");
        assert_eq!(gw.get("Compression"), None);
        assert_eq!(gw.get("HostName"), Some("gw.example.com"));
    }

    #[test]
    fn new_entry_roundtrip() {
        let mut cfg = SshConfig::default();
        let mut e = HostEntry {
            patterns: "server".into(),
            lines: Vec::new(),
        };
        e.set("HostName", "s.example.com");
        e.set("User", "root");
        cfg.blocks.push(Block::Host(e));
        let text = cfg.to_text();
        assert_eq!(text, "Host server\n    HostName s.example.com\n    User root\n");
        assert_eq!(SshConfig::parse(&text).host_block_ids().len(), 1);
    }
}


