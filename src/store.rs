//! User storage on the file system.
//!
//! Layout (by default in `~/.config/firma`, `%APPDATA%\firma` on Windows, or `$FIRMA_HOME`):
//!
//! ```text
//! users/<name>/user.toml        metadata
//! users/<name>/certificate.p12  certificate + private key (encrypted with its password)
//! users/<name>/signature.png    handwritten signature as an image, or
//! users/<name>/signature.pdf    vector handwritten signature (imported from Preview)
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserMeta {
    pub name: String,
    /// Certificate holder CN (informational, refreshed when the certificate changes).
    #[serde(default)]
    pub holder: String,
    #[serde(default)]
    pub issuer: String,
    #[serde(default)]
    pub expires: String,
}

/// Global preferences (`config.toml` in the data directory).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Default PAdES level: "b", "t", "lt" or "lta".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Time-stamping authority URL (RFC 3161).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa: Option<String>,
    /// User for TSAs that require HTTP authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_user: Option<String>,
    /// TSA policy OID to request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_policy: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    Image,
    Vector,
}

pub struct Store {
    root: PathBuf,
}

pub struct User {
    pub meta: UserMeta,
    pub dir: PathBuf,
}

impl User {
    pub fn cert_path(&self) -> PathBuf {
        self.dir.join("certificate.p12")
    }

    pub fn image_path(&self) -> PathBuf {
        self.dir.join("signature.png")
    }

    pub fn vector_path(&self) -> PathBuf {
        self.dir.join("signature.pdf")
    }

    /// The user's handwritten signature, if any (the vector one takes precedence).
    pub fn signature(&self) -> Option<(SignatureKind, PathBuf)> {
        let pdf = self.vector_path();
        if pdf.exists() {
            return Some((SignatureKind::Vector, pdf));
        }
        let png = self.image_path();
        if png.exists() {
            return Some((SignatureKind::Image, png));
        }
        None
    }

    pub fn save_meta(&self) -> Result<()> {
        write_private(&self.dir.join("user.toml"), toml::to_string_pretty(&self.meta)?.as_bytes())
    }
}

impl Store {
    pub fn open(home: Option<PathBuf>) -> Result<Self> {
        let root = match home.or_else(|| std::env::var_os("FIRMA_HOME").map(PathBuf::from)) {
            Some(p) => p,
            // Windows: %APPDATA%\firma. macOS and Linux: ~/.config/firma.
            None if cfg!(windows) => dirs::config_dir().context("could not determine %APPDATA%")?.join("firma"),
            None => dirs::home_dir()
                .context("could not determine the home directory")?
                .join(".config")
                .join("firma"),
        };
        Ok(Self { root })
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    pub fn config(&self) -> Result<Config> {
        let path = self.config_path();
        if !path.exists() {
            return Ok(Config::default());
        }
        toml::from_str(&fs::read_to_string(&path)?).with_context(|| format!("reading {}", path.display()))
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        create_private_dir(&self.root)?;
        write_private(&self.config_path(), toml::to_string_pretty(config)?.as_bytes())
    }

    fn users_dir(&self) -> PathBuf {
        self.root.join("users")
    }

    pub fn user_dir(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.users_dir().join(name))
    }

    pub fn create_user(&self, name: &str) -> Result<User> {
        let dir = self.user_dir(name)?;
        if dir.exists() {
            bail!("user '{name}' already exists");
        }
        create_private_dir(&self.root)?;
        create_private_dir(&self.users_dir())?;
        create_private_dir(&dir)?;
        let user = User { meta: UserMeta { name: name.to_string(), ..Default::default() }, dir };
        user.save_meta()?;
        Ok(user)
    }

    pub fn user(&self, name: &str) -> Result<User> {
        let dir = self.user_dir(name)?;
        let meta_path = dir.join("user.toml");
        if !meta_path.exists() {
            bail!("user '{name}' does not exist (see `firma user list`)");
        }
        let meta: UserMeta = toml::from_str(&fs::read_to_string(&meta_path)?)
            .with_context(|| format!("reading {}", meta_path.display()))?;
        Ok(User { meta, dir })
    }

    pub fn list(&self) -> Result<Vec<User>> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(self.users_dir()) else {
            return Ok(out);
        };
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if let Ok(u) = self.user(name) {
                    out.push(u);
                }
            }
        }
        out.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
        Ok(out)
    }

    pub fn remove(&self, name: &str) -> Result<()> {
        let user = self.user(name)?;
        fs::remove_dir_all(&user.dir)?;
        Ok(())
    }
}

/// Only letters, digits, `-`, `_` and `.` (not starting with a dot): the name is a directory.
fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !ok {
        bail!("invalid user name: '{name}' (use letters, digits, '-', '_' or '.')");
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes a file readable only by its owner (0600), atomically.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}
