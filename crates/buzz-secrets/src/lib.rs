use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const MAX_ACTIVE_SECRET_LEASE_ROWS: usize = 1_024;
const MAX_SECRET_POLICY_ROWS: usize = 1_024;
const MAX_POLICY_IDENTIFIER_BYTES: usize = 256;
const MAX_POLICY_ACL_ENTRIES: usize = 128;
pub const MAX_SECRET_LEASE_TTL_SECS: u64 = 3_600;
const MAX_POLICY_LIFETIME_SECS: u64 = 86_400;
pub const MAX_BWS_SECRET_BINDINGS: usize = 128;
const MAX_BWS_LOGICAL_KEY_BYTES: usize = 256;

struct BoundedZeroizingJsonBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}

impl BoundedZeroizingJsonBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            limit,
        }
    }

    fn into_inner(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

impl Write for BoundedZeroizingJsonBuffer {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("bounded JSON length overflow"))?;
        if next_len > self.limit {
            return Err(io::Error::other("bounded JSON limit exceeded"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Durable metadata binding an exact logical key to one BWS secret UUID.
/// The binding deliberately contains no secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BwsSecretBinding {
    pub logical_key: String,
    pub secret_id: String,
}

/// Validate bounded BWS metadata without normalizing logical keys.
pub fn validate_bws_secret_bindings(
    bindings: &[BwsSecretBinding],
) -> Result<BTreeMap<String, Uuid>, SecretError> {
    if bindings.len() > MAX_BWS_SECRET_BINDINGS {
        return Err(SecretError::InvalidConfig(
            "too many BWS secret bindings".to_string(),
        ));
    }
    let mut validated = BTreeMap::new();
    let mut secret_ids = HashSet::new();
    for binding in bindings {
        let key = binding.logical_key.as_str();
        if key.trim().is_empty()
            || key.len() > MAX_BWS_LOGICAL_KEY_BYTES
            || key.chars().any(char::is_control)
        {
            return Err(SecretError::InvalidConfig(
                "BWS logical key is invalid".to_string(),
            ));
        }
        let secret_id = Uuid::parse_str(&binding.secret_id).map_err(|_| {
            SecretError::InvalidConfig("BWS secret binding ID must be a UUID".to_string())
        })?;
        if validated
            .insert(binding.logical_key.clone(), secret_id)
            .is_some()
            || !secret_ids.insert(secret_id)
        {
            return Err(SecretError::InvalidConfig(
                "BWS secret bindings must be unique".to_string(),
            ));
        }
    }
    Ok(validated)
}

#[cfg(windows)]
pub fn trusted_windows_powershell_path() -> Result<PathBuf, SecretError> {
    let system_root = windows_registry::LOCAL_MACHINE
        .open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|key| key.get_string("SystemRoot"))
        .map_err(|_| {
            SecretError::InvalidConfig("trusted Windows launcher unavailable".to_string())
        })?;
    let system_root = PathBuf::from(system_root);
    if !system_root.is_absolute() {
        return Err(SecretError::InvalidConfig(
            "trusted Windows launcher unavailable".to_string(),
        ));
    }
    Ok(system_root
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
}

#[cfg(windows)]
fn trusted_windows_bws_path() -> Result<PathBuf, SecretError> {
    let path = std::env::var_os("PATH").ok_or_else(|| {
        SecretError::InvalidConfig("trusted BWS executable unavailable".to_string())
    })?;
    for directory in std::env::split_paths(&path).filter(|directory| directory.is_absolute()) {
        let candidate = directory.join("bws.exe");
        let Ok(canonical) = std::fs::canonicalize(candidate) else {
            continue;
        };
        if canonical.is_absolute()
            && canonical.is_file()
            && canonical
                .file_name()
                .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("bws.exe"))
            && !canonical
                .as_os_str()
                .to_string_lossy()
                .chars()
                .any(char::is_control)
        {
            return Ok(canonical);
        }
    }
    Err(SecretError::InvalidConfig(
        "trusted BWS executable unavailable".to_string(),
    ))
}

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Provider error ({provider}): {message}")]
    ProviderError { provider: String, message: String },

    #[error("Authorization denied: agent {agent_pubkey} is not authorized for secret {secret_key} on tool {tool}")]
    AccessDenied {
        agent_pubkey: String,
        secret_key: String,
        tool: String,
    },

    #[error("Lease expired for secret {0}")]
    LeaseExpired(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("IO/Process error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Secret audit store error: {0}")]
    Audit(String),
}

/// Metadata describing a secret entry without exposing its sensitive value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub key: String,
    pub description: Option<String>,
    pub provider: String,
    pub updated_at: DateTime<Utc>,
}

/// Pluggable SPI for secret backends (OS Keyring, BWS, HashiCorp Vault, KeePassXC, etc.)
#[async_trait]
pub trait SecretVaultProvider: Send + Sync {
    /// Identifier of the provider (e.g. "os-keyring", "bws", "memory").
    fn name(&self) -> &str;

    /// Retrieve a secret value by key.
    async fn get_secret(&self, key: &str) -> Result<String, SecretError>;

    /// Store or update a secret value by key.
    async fn set_secret(
        &self,
        key: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<(), SecretError>;

    /// Delete a secret by key.
    async fn delete_secret(&self, key: &str) -> Result<(), SecretError>;

    /// List available secret metadata.
    async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError>;
}

/// Attribute-Based Access Control (ABAC) Policy for an agent invoking tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    /// Capability/session identifier owning this policy.
    pub policy_id: String,
    /// Agent pubkey (hex or npub prefix).
    pub agent_pubkey: String,
    /// Secret keys this agent is permitted to lease.
    pub allowed_secrets: Vec<String>,
    /// Specific tools permitted to consume the secret (e.g. ["web_search", "github"]).
    pub allowed_tools: Vec<String>,
    /// Maximum lease duration in seconds (default 300 = 5 minutes).
    pub max_lease_ttl_secs: u64,
    /// Exact capability/session expiry.
    pub expires_at: DateTime<Utc>,
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_POLICY_IDENTIFIER_BYTES
        && !value.chars().any(char::is_control)
}

fn validate_policy_at(policy: &SecretPolicy, now: DateTime<Utc>) -> Result<(), SecretError> {
    let valid_acls = |entries: &[String]| {
        !entries.is_empty()
            && entries.len() <= MAX_POLICY_ACL_ENTRIES
            && entries.iter().all(|entry| valid_identifier(entry))
    };
    let max_expiry = now
        .checked_add_signed(chrono::Duration::seconds(MAX_POLICY_LIFETIME_SECS as i64))
        .ok_or_else(|| {
            SecretError::InvalidConfig("secret policy lifetime exceeds clock range".to_string())
        })?;
    if !valid_identifier(&policy.policy_id)
        || !valid_identifier(&policy.agent_pubkey)
        || !valid_acls(&policy.allowed_secrets)
        || !valid_acls(&policy.allowed_tools)
        || policy.max_lease_ttl_secs == 0
        || policy.max_lease_ttl_secs > MAX_SECRET_LEASE_TTL_SECS
        || policy.expires_at <= now
        || policy.expires_at > max_expiry
    {
        return Err(SecretError::InvalidConfig(
            "secret policy violates identity, ACL, TTL, or lifetime bounds".to_string(),
        ));
    }
    Ok(())
}

/// A time-bounded, tool-scoped secret lease for an agent execution turn.
pub struct SecretLease {
    pub lease_id: String,
    pub secret_key: String,
    pub value: String,
    pub agent_pubkey: String,
    pub tool: String,
    pub expires_at: DateTime<Utc>,
}

impl SecretLease {
    pub fn is_valid(&self) -> bool {
        Utc::now() < self.expires_at
    }
}

impl std::fmt::Debug for SecretLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretLease")
            .field("lease_id", &self.lease_id)
            .field("secret_key", &self.secret_key)
            .field("value", &"[REDACTED]")
            .field("agent_pubkey", &self.agent_pubkey)
            .field("tool", &self.tool)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl Drop for SecretLease {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Secret-safe projection used by settings and audit surfaces. It deliberately
/// omits the leased value so frontend callers can never recover credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretLeaseMetadata {
    pub lease_id: String,
    pub secret_key: String,
    pub agent_pubkey: String,
    pub tool: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

fn validate_lease_metadata_at(
    lease: &SecretLeaseMetadata,
    now: DateTime<Utc>,
) -> Result<(), SecretError> {
    let canonical_lease_id = lease
        .lease_id
        .strip_prefix("lease_")
        .and_then(|value| Uuid::parse_str(value).ok())
        .map(|value| format!("lease_{value}"))
        .ok_or_else(|| {
            SecretError::InvalidConfig("secret lease metadata is invalid".to_string())
        })?;
    let future_skew = now
        .checked_add_signed(chrono::Duration::seconds(30))
        .ok_or_else(|| {
            SecretError::InvalidConfig("secret lease clock range is invalid".to_string())
        })?;
    let max_expiry = lease
        .issued_at
        .checked_add_signed(chrono::Duration::seconds(MAX_SECRET_LEASE_TTL_SECS as i64))
        .ok_or_else(|| {
            SecretError::InvalidConfig("secret lease clock range is invalid".to_string())
        })?;
    if canonical_lease_id != lease.lease_id
        || !valid_identifier(&lease.secret_key)
        || !valid_identifier(&lease.agent_pubkey)
        || !valid_identifier(&lease.tool)
        || lease.issued_at > future_skew
        || lease.expires_at <= now
        || lease.expires_at <= lease.issued_at
        || lease.expires_at > max_expiry
    {
        return Err(SecretError::InvalidConfig(
            "secret lease metadata is invalid".to_string(),
        ));
    }
    Ok(())
}

/// Shared, metadata-only control plane for secret ACLs and active leases. Raw
/// secret values are never accepted by this store.
#[derive(Debug, Clone)]
pub struct SecretAuditStore {
    path: PathBuf,
}

impl SecretAuditStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SecretError> {
        let store = Self { path: path.into() };
        let _ = store.connect()?;
        Ok(store)
    }

    pub fn open_default() -> Result<Self, SecretError> {
        Self::open(default_audit_path()?)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn connect(&self) -> Result<Connection, SecretError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(&self.path).map_err(audit_error)?;
        connection
            .busy_timeout(std::time::Duration::from_millis(5_000))
            .map_err(audit_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(audit_error)?;
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS secret_policies_v2 (
                    policy_id TEXT PRIMARY KEY NOT NULL,
                    agent_pubkey TEXT NOT NULL,
                    allowed_secrets_json TEXT NOT NULL,
                    allowed_tools_json TEXT NOT NULL,
                    max_lease_ttl_secs INTEGER NOT NULL,
                    expires_at_unix_ms INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS active_secret_leases (
                    lease_id TEXT PRIMARY KEY NOT NULL,
                    secret_key TEXT NOT NULL,
                    agent_pubkey TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    issued_at_unix_ms INTEGER NOT NULL,
                    expires_at_unix_ms INTEGER NOT NULL
                );",
            )
            .map_err(audit_error)?;
        Ok(connection)
    }

    pub fn set_policy(&self, policy: &SecretPolicy) -> Result<(), SecretError> {
        let now = Utc::now();
        validate_policy_at(policy, now)?;
        let allowed_secrets = serde_json::to_string(&policy.allowed_secrets)
            .map_err(|error| SecretError::Audit(error.to_string()))?;
        let allowed_tools = serde_json::to_string(&policy.allowed_tools)
            .map_err(|error| SecretError::Audit(error.to_string()))?;
        let ttl = i64::try_from(policy.max_lease_ttl_secs)
            .map_err(|_| SecretError::Audit("policy TTL exceeds SQLite range".to_string()))?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction().map_err(audit_error)?;
        transaction
            .execute(
                "DELETE FROM secret_policies_v2 WHERE expires_at_unix_ms <= ?1",
                [now.timestamp_millis()],
            )
            .map_err(audit_error)?;
        let exists = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM secret_policies_v2 WHERE policy_id = ?1
                 )",
                [&policy.policy_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(audit_error)?;
        if !exists {
            let count = transaction
                .query_row("SELECT COUNT(*) FROM secret_policies_v2", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(audit_error)?;
            if count >= MAX_SECRET_POLICY_ROWS as i64 {
                transaction.commit().map_err(audit_error)?;
                return Err(SecretError::InvalidConfig(
                    "secret policy capacity reached".to_string(),
                ));
            }
        }
        transaction
            .execute(
                "INSERT INTO secret_policies_v2
                    (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                     max_lease_ttl_secs, expires_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(policy_id) DO UPDATE SET
                    agent_pubkey = excluded.agent_pubkey,
                    allowed_secrets_json = excluded.allowed_secrets_json,
                    allowed_tools_json = excluded.allowed_tools_json,
                    max_lease_ttl_secs = excluded.max_lease_ttl_secs,
                    expires_at_unix_ms = excluded.expires_at_unix_ms",
                params![
                    policy.policy_id,
                    policy.agent_pubkey,
                    allowed_secrets,
                    allowed_tools,
                    ttl,
                    policy.expires_at.timestamp_millis(),
                ],
            )
            .map_err(audit_error)?;
        transaction.commit().map_err(audit_error)?;
        Ok(())
    }

    pub fn policies(&self) -> Result<Vec<SecretPolicy>, SecretError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction().map_err(audit_error)?;
        let now = Utc::now();
        transaction
            .execute(
                "DELETE FROM secret_policies_v2 WHERE expires_at_unix_ms <= ?1",
                [now.timestamp_millis()],
            )
            .map_err(audit_error)?;
        transaction
            .execute(
                "DELETE FROM secret_policies_v2
                 WHERE policy_id IN (
                     SELECT policy_id FROM secret_policies_v2
                     ORDER BY expires_at_unix_ms DESC, policy_id DESC
                     LIMIT -1 OFFSET ?1
                 )",
                [MAX_SECRET_POLICY_ROWS as i64],
            )
            .map_err(audit_error)?;
        let rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT rowid, policy_id, agent_pubkey, allowed_secrets_json,
                            allowed_tools_json, max_lease_ttl_secs, expires_at_unix_ms
                     FROM secret_policies_v2
                     ORDER BY expires_at_unix_ms DESC, policy_id DESC
                     LIMIT ?1",
                )
                .map_err(audit_error)?;
            let mapped = statement
                .query_map([MAX_SECRET_POLICY_ROWS as i64], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1).ok(),
                        row.get::<_, String>(2).ok(),
                        row.get::<_, String>(3).ok(),
                        row.get::<_, String>(4).ok(),
                        row.get::<_, i64>(5).ok(),
                        row.get::<_, i64>(6).ok(),
                    ))
                })
                .map_err(audit_error)?;
            mapped.collect::<Result<Vec<_>, _>>().map_err(audit_error)?
        };
        let mut policies = Vec::new();
        let mut invalid_rowids = Vec::new();
        for (
            rowid,
            policy_id,
            agent_pubkey,
            allowed_secrets_json,
            allowed_tools_json,
            ttl,
            expires_at,
        ) in rows
        {
            let policy = match (
                policy_id,
                agent_pubkey,
                allowed_secrets_json,
                allowed_tools_json,
                ttl,
                expires_at,
            ) {
                (
                    Some(policy_id),
                    Some(agent_pubkey),
                    Some(allowed_secrets_json),
                    Some(allowed_tools_json),
                    Some(ttl),
                    Some(expires_at),
                ) => {
                    let allowed_secrets =
                        serde_json::from_str::<Vec<String>>(&allowed_secrets_json);
                    let allowed_tools = serde_json::from_str::<Vec<String>>(&allowed_tools_json);
                    match (
                        allowed_secrets,
                        allowed_tools,
                        u64::try_from(ttl),
                        Utc.timestamp_millis_opt(expires_at).single(),
                    ) {
                        (Ok(allowed_secrets), Ok(allowed_tools), Ok(ttl), Some(expires_at)) => {
                            Some(SecretPolicy {
                                policy_id,
                                agent_pubkey,
                                allowed_secrets,
                                allowed_tools,
                                max_lease_ttl_secs: ttl,
                                expires_at,
                            })
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            match policy {
                Some(policy) if validate_policy_at(&policy, now).is_ok() => policies.push(policy),
                _ => invalid_rowids.push(rowid),
            }
        }
        for rowid in invalid_rowids {
            transaction
                .execute("DELETE FROM secret_policies_v2 WHERE rowid = ?1", [rowid])
                .map_err(audit_error)?;
        }
        transaction.commit().map_err(audit_error)?;
        Ok(policies)
    }

    pub fn remove_policy(&self, policy_id: &str) -> Result<(), SecretError> {
        self.connect()?
            .execute(
                "DELETE FROM secret_policies_v2 WHERE policy_id = ?1",
                [policy_id],
            )
            .map_err(audit_error)?;
        Ok(())
    }

    pub fn record_lease(&self, lease: &SecretLeaseMetadata) -> Result<(), SecretError> {
        validate_lease_metadata_at(lease, Utc::now())?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction().map_err(audit_error)?;
        transaction
            .execute(
                "DELETE FROM active_secret_leases WHERE expires_at_unix_ms <= ?1",
                [Utc::now().timestamp_millis()],
            )
            .map_err(audit_error)?;
        transaction
            .execute(
                "INSERT OR REPLACE INTO active_secret_leases
                    (lease_id, secret_key, agent_pubkey, tool,
                     issued_at_unix_ms, expires_at_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    lease.lease_id,
                    lease.secret_key,
                    lease.agent_pubkey,
                    lease.tool,
                    lease.issued_at.timestamp_millis(),
                    lease.expires_at.timestamp_millis(),
                ],
            )
            .map_err(audit_error)?;
        transaction
            .execute(
                "DELETE FROM active_secret_leases
                 WHERE lease_id IN (
                    SELECT lease_id FROM active_secret_leases
                    ORDER BY issued_at_unix_ms DESC, lease_id DESC
                    LIMIT -1 OFFSET ?1
                 )",
                [MAX_ACTIVE_SECRET_LEASE_ROWS as i64],
            )
            .map_err(audit_error)?;
        transaction.commit().map_err(audit_error)?;
        Ok(())
    }

    pub fn active_leases(&self) -> Result<Vec<SecretLeaseMetadata>, SecretError> {
        let now = Utc::now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction().map_err(audit_error)?;
        transaction
            .execute(
                "DELETE FROM active_secret_leases WHERE expires_at_unix_ms <= ?1",
                [now.timestamp_millis()],
            )
            .map_err(audit_error)?;
        transaction
            .execute(
                "DELETE FROM active_secret_leases
                 WHERE rowid IN (
                    SELECT rowid FROM active_secret_leases
                    ORDER BY issued_at_unix_ms DESC, lease_id DESC
                    LIMIT -1 OFFSET ?1
                 )",
                [MAX_ACTIVE_SECRET_LEASE_ROWS as i64],
            )
            .map_err(audit_error)?;
        let rows = {
            let mut statement = transaction
                .prepare(
                    "SELECT rowid, lease_id, secret_key, agent_pubkey, tool,
                            issued_at_unix_ms, expires_at_unix_ms
                     FROM active_secret_leases
                     ORDER BY expires_at_unix_ms, lease_id
                     LIMIT ?1",
                )
                .map_err(audit_error)?;
            let mapped = statement
                .query_map([MAX_ACTIVE_SECRET_LEASE_ROWS as i64], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1).ok(),
                        row.get::<_, String>(2).ok(),
                        row.get::<_, String>(3).ok(),
                        row.get::<_, String>(4).ok(),
                        row.get::<_, i64>(5).ok(),
                        row.get::<_, i64>(6).ok(),
                    ))
                })
                .map_err(audit_error)?;
            mapped.collect::<Result<Vec<_>, _>>().map_err(audit_error)?
        };
        let mut leases = Vec::new();
        let mut invalid_rowids = Vec::new();
        for (rowid, lease_id, secret_key, agent_pubkey, tool, issued_at, expires_at) in rows {
            let lease = match (
                lease_id,
                secret_key,
                agent_pubkey,
                tool,
                issued_at,
                expires_at,
            ) {
                (
                    Some(lease_id),
                    Some(secret_key),
                    Some(agent_pubkey),
                    Some(tool),
                    Some(issued_at),
                    Some(expires_at),
                ) => match (
                    Utc.timestamp_millis_opt(issued_at).single(),
                    Utc.timestamp_millis_opt(expires_at).single(),
                ) {
                    (Some(issued_at), Some(expires_at)) => Some(SecretLeaseMetadata {
                        lease_id,
                        secret_key,
                        agent_pubkey,
                        tool,
                        issued_at,
                        expires_at,
                    }),
                    _ => None,
                },
                _ => None,
            };
            match lease {
                Some(lease) if validate_lease_metadata_at(&lease, now).is_ok() => {
                    leases.push(lease);
                }
                Some(_) | None => invalid_rowids.push(rowid),
            }
        }
        for rowid in invalid_rowids {
            transaction
                .execute("DELETE FROM active_secret_leases WHERE rowid = ?1", [rowid])
                .map_err(audit_error)?;
        }
        transaction.commit().map_err(audit_error)?;
        Ok(leases)
    }
}

fn audit_error(error: rusqlite::Error) -> SecretError {
    SecretError::Audit(error.to_string())
}

fn default_audit_path() -> Result<PathBuf, SecretError> {
    if let Some(path) = std::env::var_os("BUZZ_SECRET_AUDIT_DB") {
        let path = PathBuf::from(path);
        if path.as_os_str().is_empty() {
            return Err(SecretError::InvalidConfig(
                "BUZZ_SECRET_AUDIT_DB is empty".to_string(),
            ));
        }
        return Ok(path);
    }
    let base = std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("XDG_DATA_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(|| {
            SecretError::InvalidConfig("local data directory unavailable".to_string())
        })?;
    Ok(base.join("Buzz").join("secret-access.db"))
}

type StoredSecret = (String, Option<String>, DateTime<Utc>);

/// Memory-backed secret provider for unit testing and ephemeral sandboxes.
pub struct InMemorySecretVault {
    secrets: tokio::sync::RwLock<HashMap<String, StoredSecret>>,
}

impl InMemorySecretVault {
    pub fn new() -> Self {
        Self {
            secrets: tokio::sync::RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySecretVault {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretVaultProvider for InMemorySecretVault {
    fn name(&self) -> &str {
        "in-memory"
    }

    async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
        let lock = self.secrets.read().await;
        lock.get(key)
            .map(|(v, _, _)| v.clone())
            .ok_or_else(|| SecretError::NotFound(key.to_string()))
    }

    async fn set_secret(
        &self,
        key: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<(), SecretError> {
        let mut lock = self.secrets.write().await;
        lock.insert(
            key.to_string(),
            (
                value.to_string(),
                description.map(str::to_string),
                Utc::now(),
            ),
        );
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
        let mut lock = self.secrets.write().await;
        lock.remove(key)
            .map(|_| ())
            .ok_or_else(|| SecretError::NotFound(key.to_string()))
    }

    async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError> {
        let lock = self.secrets.read().await;
        Ok(lock
            .iter()
            .map(|(k, (_, desc, updated_at))| SecretMetadata {
                key: k.clone(),
                description: desc.clone(),
                provider: self.name().to_string(),
                updated_at: *updated_at,
            })
            .collect())
    }
}

/// Central Secret Broker managing providers, layered fallback, and ABAC leasing.
pub struct SecretBroker {
    providers: Vec<Arc<dyn SecretVaultProvider>>,
    policies: RwLock<HashMap<String, SecretPolicy>>,
    active_leases: RwLock<HashMap<String, SecretLeaseMetadata>>,
    audit: Option<Arc<SecretAuditStore>>,
}

impl SecretBroker {
    pub fn new(providers: Vec<Arc<dyn SecretVaultProvider>>) -> Self {
        Self {
            providers,
            policies: RwLock::new(HashMap::new()),
            active_leases: RwLock::new(HashMap::new()),
            audit: None,
        }
    }

    pub fn with_audit(
        providers: Vec<Arc<dyn SecretVaultProvider>>,
        audit: Arc<SecretAuditStore>,
    ) -> Self {
        Self {
            providers,
            policies: RwLock::new(HashMap::new()),
            active_leases: RwLock::new(HashMap::new()),
            audit: Some(audit),
        }
    }

    pub fn set_policy(&self, policy: SecretPolicy) -> Result<(), SecretError> {
        let now = Utc::now();
        validate_policy_at(&policy, now)?;
        let mut policies = self
            .policies
            .write()
            .map_err(|_| SecretError::Audit("policy lock poisoned".to_string()))?;
        if let Some(audit) = &self.audit {
            let live_count = policies
                .values()
                .filter(|existing| existing.expires_at > now)
                .count();
            let updates_live_policy = policies
                .get(&policy.policy_id)
                .is_some_and(|existing| existing.expires_at > now);
            if !updates_live_policy && live_count >= MAX_SECRET_POLICY_ROWS {
                return Err(SecretError::InvalidConfig(
                    "secret policy capacity reached".to_string(),
                ));
            }
            audit.set_policy(&policy)?;
            policies.retain(|_, existing| existing.expires_at > now);
        } else {
            policies.retain(|_, existing| existing.expires_at > now);
            if !policies.contains_key(&policy.policy_id) && policies.len() >= MAX_SECRET_POLICY_ROWS
            {
                return Err(SecretError::InvalidConfig(
                    "secret policy capacity reached".to_string(),
                ));
            }
        }
        policies.insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    pub async fn add_policy(&self, policy: SecretPolicy) -> Result<(), SecretError> {
        self.set_policy(policy)
    }

    pub fn remove_policy(&self, policy_id: &str) -> Result<(), SecretError> {
        let mut policies = self
            .policies
            .write()
            .map_err(|_| SecretError::Audit("policy lock poisoned".to_string()))?;
        if let Some(audit) = &self.audit {
            audit.remove_policy(policy_id)?;
        }
        policies.remove(policy_id);
        Ok(())
    }

    /// Return configured policy metadata for read-only ACL inspection.
    pub async fn policies(&self) -> Result<Vec<SecretPolicy>, SecretError> {
        if let Some(audit) = &self.audit {
            return audit.policies();
        }
        let now = Utc::now();
        let mut lock = self
            .policies
            .write()
            .map_err(|_| SecretError::Audit("policy lock poisoned".to_string()))?;
        lock.retain(|_, policy| policy.expires_at > now);
        let mut policies: Vec<_> = lock.values().cloned().collect();
        policies.sort_by(|a, b| a.policy_id.cmp(&b.policy_id));
        Ok(policies)
    }

    /// Return only unexpired leases and remove expired audit entries.
    pub async fn active_leases(&self) -> Result<Vec<SecretLeaseMetadata>, SecretError> {
        if let Some(audit) = &self.audit {
            return audit.active_leases();
        }
        let now = Utc::now();
        let mut lock = self
            .active_leases
            .write()
            .map_err(|_| SecretError::Audit("lease lock poisoned".to_string()))?;
        lock.retain(|_, lease| lease.expires_at > now);
        let mut leases: Vec<_> = lock.values().cloned().collect();
        leases.sort_by_key(|lease| lease.expires_at);
        Ok(leases)
    }

    /// Resolve a secret across registered providers in priority order.
    pub async fn resolve_secret(&self, key: &str) -> Result<String, SecretError> {
        for provider in &self.providers {
            match provider.get_secret(key).await {
                Ok(value) => return Ok(value),
                Err(SecretError::NotFound(_)) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(SecretError::NotFound(key.to_string()))
    }

    /// Issue an ABAC-gated lease bounded by the policy's exact expiry.
    pub async fn acquire_lease(
        &self,
        policy_id: &str,
        agent_pubkey: &str,
        tool: &str,
        secret_key: &str,
    ) -> Result<SecretLease, SecretError> {
        let policy_expiry = self
            .policies
            .read()
            .map_err(|_| SecretError::Audit("policy lock poisoned".to_string()))?
            .get(policy_id)
            .filter(|policy| policy.agent_pubkey == agent_pubkey)
            .map(|policy| policy.expires_at.timestamp_millis())
            .ok_or_else(|| SecretError::AccessDenied {
                agent_pubkey: agent_pubkey.to_string(),
                secret_key: secret_key.to_string(),
                tool: tool.to_string(),
            })?;
        self.acquire_lease_until_ms(policy_id, agent_pubkey, tool, secret_key, policy_expiry)
            .await
    }

    /// Issue a lease bounded by both the policy and exact capability deadline.
    pub async fn acquire_lease_until_ms(
        &self,
        policy_id: &str,
        agent_pubkey: &str,
        tool: &str,
        secret_key: &str,
        capability_expires_at_unix_ms: i64,
    ) -> Result<SecretLease, SecretError> {
        let denied = || SecretError::AccessDenied {
            agent_pubkey: agent_pubkey.to_string(),
            secret_key: secret_key.to_string(),
            tool: tool.to_string(),
        };
        let capability_expiry = Utc
            .timestamp_millis_opt(capability_expires_at_unix_ms)
            .single()
            .ok_or_else(|| {
                SecretError::InvalidConfig(
                    "capability expiry is outside the clock range".to_string(),
                )
            })?;

        {
            let policies = self
                .policies
                .read()
                .map_err(|_| SecretError::Audit("policy lock poisoned".to_string()))?;
            let policy = policies
                .get(policy_id)
                .filter(|policy| policy.agent_pubkey == agent_pubkey)
                .ok_or_else(&denied)?;
            let now = Utc::now();
            if policy.expires_at <= now
                || capability_expiry <= now
                || !policy
                    .allowed_secrets
                    .iter()
                    .any(|secret| secret == secret_key)
                || !policy.allowed_tools.iter().any(|allowed| allowed == tool)
            {
                return Err(denied());
            }
            i64::try_from(policy.max_lease_ttl_secs).map_err(|_| {
                SecretError::InvalidConfig("lease TTL exceeds clock range".to_string())
            })?;
        }

        let mut secret_value = Zeroizing::new(self.resolve_secret(secret_key).await?);

        // This is the linearization point for issuance versus policy mutation.
        // The authoritative policy read lock remains held until both durable and
        // in-memory lease metadata are inserted, so removal/narrowing cannot race
        // a lease into existence after this revalidation.
        let policies = self
            .policies
            .read()
            .map_err(|_| SecretError::Audit("policy lock poisoned".to_string()))?;
        let policy = policies
            .get(policy_id)
            .filter(|policy| policy.agent_pubkey == agent_pubkey)
            .ok_or_else(&denied)?;
        let fulfilled_at = Utc::now();
        if policy.expires_at <= fulfilled_at
            || capability_expiry <= fulfilled_at
            || !policy
                .allowed_secrets
                .iter()
                .any(|secret| secret == secret_key)
            || !policy.allowed_tools.iter().any(|allowed| allowed == tool)
        {
            return Err(denied());
        }
        let ttl = i64::try_from(policy.max_lease_ttl_secs)
            .map_err(|_| SecretError::InvalidConfig("lease TTL exceeds clock range".to_string()))?;
        let ttl_expiry = fulfilled_at
            .checked_add_signed(chrono::Duration::seconds(ttl))
            .ok_or_else(|| {
                SecretError::InvalidConfig("lease TTL exceeds clock range".to_string())
            })?;
        let expires_at = policy.expires_at.min(capability_expiry).min(ttl_expiry);
        if expires_at <= fulfilled_at {
            return Err(denied());
        }

        let lease_id = format!("lease_{}", Uuid::new_v4());
        let metadata = SecretLeaseMetadata {
            lease_id: lease_id.clone(),
            secret_key: secret_key.to_string(),
            agent_pubkey: agent_pubkey.to_string(),
            tool: tool.to_string(),
            issued_at: fulfilled_at,
            expires_at,
        };
        if let Some(audit) = &self.audit {
            audit.record_lease(&metadata)?;
        }
        let mut active_leases = self
            .active_leases
            .write()
            .map_err(|_| SecretError::Audit("lease lock poisoned".to_string()))?;
        active_leases.retain(|_, lease| lease.expires_at > fulfilled_at);
        active_leases.insert(lease_id.clone(), metadata);
        if active_leases.len() > MAX_ACTIVE_SECRET_LEASE_ROWS {
            let mut oldest: Vec<_> = active_leases
                .values()
                .map(|lease| (lease.issued_at, lease.lease_id.clone()))
                .collect();
            oldest.sort_unstable();
            let remove_count = active_leases.len() - MAX_ACTIVE_SECRET_LEASE_ROWS;
            for (_, stale_lease_id) in oldest.into_iter().take(remove_count) {
                active_leases.remove(&stale_lease_id);
            }
        }
        drop(active_leases);
        drop(policies);

        Ok(SecretLease {
            lease_id,
            secret_key: secret_key.to_string(),
            value: std::mem::take(&mut *secret_value),
            agent_pubkey: agent_pubkey.to_string(),
            tool: tool.to_string(),
            expires_at,
        })
    }
}

#[cfg(feature = "bws")]
pub use bws_provider::BwsVault;
#[cfg(feature = "os-keyring")]
pub use keyring_provider::OsKeyringVault;

pub const PROVIDER_CONFIG_SERVICE: &str = "buzz-secret-provider-config";
pub const PROVIDER_BACKEND_KEY: &str = "SECRET_BACKEND";
pub const PROVIDER_BWS_CONFIG_KEY: &str = "BWS_CONFIG_V1";

const BWS_KEYRING_SCHEMA_VERSION: u8 = 2;
const BWS_KEYRING_BINDING_PREFIX: &str = "BWS_BINDING_V2";
const WINDOWS_CREDENTIAL_BLOB_MAX_BYTES: usize = 2_560;
// Windows Credential Manager enforces its blob ceiling after UTF-16 encoding.
// Keep the serialized root well below half that ceiling so ASCII-heavy machine
// tokens and JSON framing remain safe without relying on provider internals.
const BWS_KEYRING_ROOT_MAX_BYTES: usize = 1_200;
const BWS_KEYRING_BINDING_MAX_BYTES: usize = 1_024;
const MAX_BWS_ACCESS_TOKEN_BYTES: usize = 768;

static BWS_KEYRING_TRANSACTION_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn bws_keyring_transaction_lock() -> &'static tokio::sync::Mutex<()> {
    BWS_KEYRING_TRANSACTION_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub struct BwsKeyringConfig {
    pub access_token: Zeroizing<String>,
    pub project_id: String,
    pub bindings: Vec<BwsSecretBinding>,
}

impl BwsKeyringConfig {
    pub fn new(
        access_token: Zeroizing<String>,
        project_id: String,
        bindings: Vec<BwsSecretBinding>,
    ) -> Result<Self, SecretError> {
        if !(20..=MAX_BWS_ACCESS_TOKEN_BYTES).contains(&access_token.len())
            || access_token
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(SecretError::InvalidConfig(
                "BWS access token format is invalid".to_string(),
            ));
        }
        let project_id = Uuid::parse_str(project_id.trim())
            .map_err(|_| {
                SecretError::InvalidConfig("BWS project scope must be a UUID".to_string())
            })?
            .to_string();
        let bindings = validate_bws_secret_bindings(&bindings)?
            .into_iter()
            .map(|(logical_key, secret_id)| BwsSecretBinding {
                logical_key,
                secret_id: secret_id.to_string(),
            })
            .collect();
        Ok(Self {
            access_token,
            project_id,
            bindings,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct StoredBwsKeyringRoot {
    schema_version: u8,
    access_token: Zeroizing<String>,
    project_id: String,
    generation: Uuid,
    binding_count: usize,
    bindings_sha256: String,
}

#[derive(Serialize, Deserialize)]
struct StoredBwsKeyringBinding {
    schema_version: u8,
    generation: Uuid,
    index: usize,
    logical_key: String,
    secret_id: String,
}

fn bws_binding_generation_prefix(generation: Uuid) -> String {
    format!("{BWS_KEYRING_BINDING_PREFIX}:{generation}:")
}

fn bws_binding_record_key(generation: Uuid, index: usize) -> String {
    format!("{}{index:03}", bws_binding_generation_prefix(generation))
}

fn bws_bindings_digest(bindings: &[BwsSecretBinding]) -> Result<[u8; 32], SecretError> {
    let mut hasher = Sha256::new();
    for binding in bindings {
        let secret_id = Uuid::parse_str(&binding.secret_id).map_err(|_| {
            SecretError::InvalidConfig("BWS secret binding UUID is invalid".to_string())
        })?;
        let key_len = u32::try_from(binding.logical_key.len())
            .map_err(|_| SecretError::InvalidConfig("BWS logical key is too large".to_string()))?;
        hasher.update(key_len.to_be_bytes());
        hasher.update(binding.logical_key.as_bytes());
        hasher.update(secret_id.as_bytes());
    }
    Ok(hasher.finalize().into())
}

fn encode_digest(digest: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_digest(encoded: &str) -> Result<[u8; 32], SecretError> {
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(SecretError::InvalidConfig(
            "stored BWS configuration is invalid".to_string(),
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).map_err(|_| {
            SecretError::InvalidConfig("stored BWS configuration is invalid".to_string())
        })?;
    }
    Ok(digest)
}

fn digest_matches(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_stored_bws_root(root: &StoredBwsKeyringRoot) -> Result<[u8; 32], SecretError> {
    if root.schema_version != BWS_KEYRING_SCHEMA_VERSION
        || root.binding_count > MAX_BWS_SECRET_BINDINGS
        || !(20..=MAX_BWS_ACCESS_TOKEN_BYTES).contains(&root.access_token.len())
        || root
            .access_token
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || Uuid::parse_str(&root.project_id)
            .map(|project_id| project_id.to_string() != root.project_id)
            .unwrap_or(true)
    {
        return Err(SecretError::InvalidConfig(
            "stored BWS configuration is invalid".to_string(),
        ));
    }
    decode_digest(&root.bindings_sha256)
}

fn parse_stored_bws_root(value: &str) -> Result<StoredBwsKeyringRoot, SecretError> {
    if value.len() > BWS_KEYRING_ROOT_MAX_BYTES {
        return Err(SecretError::InvalidConfig(
            "stored BWS configuration is invalid".to_string(),
        ));
    }
    let root: StoredBwsKeyringRoot = serde_json::from_str(value).map_err(|_| {
        SecretError::InvalidConfig("stored BWS configuration is invalid".to_string())
    })?;
    validate_stored_bws_root(&root)?;
    Ok(root)
}

async fn load_bws_keyring_config_inner(
    store: &dyn SecretVaultProvider,
) -> Result<Option<BwsKeyringConfig>, SecretError> {
    let root_value = match store.get_secret(PROVIDER_BWS_CONFIG_KEY).await {
        Ok(value) => Zeroizing::new(value),
        Err(SecretError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut root = parse_stored_bws_root(root_value.as_str())?;
    let expected_digest = decode_digest(&root.bindings_sha256)?;
    let mut bindings = Vec::with_capacity(root.binding_count);
    for index in 0..root.binding_count {
        let key = bws_binding_record_key(root.generation, index);
        let value = store.get_secret(&key).await.map_err(|_| {
            SecretError::InvalidConfig("stored BWS configuration is invalid".to_string())
        })?;
        if value.len() > BWS_KEYRING_BINDING_MAX_BYTES {
            return Err(SecretError::InvalidConfig(
                "stored BWS configuration is invalid".to_string(),
            ));
        }
        let item: StoredBwsKeyringBinding = serde_json::from_str(&value).map_err(|_| {
            SecretError::InvalidConfig("stored BWS configuration is invalid".to_string())
        })?;
        if item.schema_version != BWS_KEYRING_SCHEMA_VERSION
            || item.generation != root.generation
            || item.index != index
        {
            return Err(SecretError::InvalidConfig(
                "stored BWS configuration is invalid".to_string(),
            ));
        }
        bindings.push(BwsSecretBinding {
            logical_key: item.logical_key,
            secret_id: item.secret_id,
        });
    }
    let access_token = std::mem::take(&mut root.access_token);
    let config = BwsKeyringConfig::new(access_token, root.project_id.clone(), bindings)?;
    let actual_digest = bws_bindings_digest(&config.bindings)?;
    if !digest_matches(&actual_digest, &expected_digest) {
        return Err(SecretError::InvalidConfig(
            "stored BWS configuration is invalid".to_string(),
        ));
    }
    Ok(Some(config))
}

pub async fn load_bws_keyring_config(
    store: &dyn SecretVaultProvider,
) -> Result<Option<BwsKeyringConfig>, SecretError> {
    let _guard = bws_keyring_transaction_lock().lock().await;
    load_bws_keyring_config_inner(store).await
}

async fn delete_bws_binding_generation(
    store: &dyn SecretVaultProvider,
    generation: Uuid,
    count: usize,
) {
    for index in 0..count.min(MAX_BWS_SECRET_BINDINGS) {
        let _ = store
            .delete_secret(&bws_binding_record_key(generation, index))
            .await;
    }
}

fn configs_match(left: &BwsKeyringConfig, right: &BwsKeyringConfig) -> bool {
    let token_matches = left.access_token.len() == right.access_token.len()
        && left
            .access_token
            .as_bytes()
            .iter()
            .zip(right.access_token.as_bytes())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0;
    token_matches
        && left.project_id == right.project_id
        && left.bindings.len() == right.bindings.len()
        && left
            .bindings
            .iter()
            .zip(&right.bindings)
            .all(|(left, right)| {
                left.logical_key == right.logical_key && left.secret_id == right.secret_id
            })
}

async fn store_bws_keyring_config_inner(
    store: &dyn SecretVaultProvider,
    config: &BwsKeyringConfig,
    generation: Uuid,
) -> Result<(), SecretError> {
    let canonical = BwsKeyringConfig::new(
        Zeroizing::new(config.access_token.to_string()),
        config.project_id.clone(),
        config.bindings.clone(),
    )?;
    let old_root_value = match store.get_secret(PROVIDER_BWS_CONFIG_KEY).await {
        Ok(value) => Some(Zeroizing::new(value)),
        Err(SecretError::NotFound(_)) => None,
        Err(error) => return Err(error),
    };
    let old_root_metadata = old_root_value
        .as_deref()
        .and_then(|value| parse_stored_bws_root(value).ok())
        .map(|root| (root.generation, root.binding_count));

    for (index, binding) in canonical.bindings.iter().enumerate() {
        let record = StoredBwsKeyringBinding {
            schema_version: BWS_KEYRING_SCHEMA_VERSION,
            generation,
            index,
            logical_key: binding.logical_key.clone(),
            secret_id: binding.secret_id.clone(),
        };
        let value = serde_json::to_string(&record).map_err(|_| {
            SecretError::InvalidConfig("BWS keyring binding is invalid".to_string())
        })?;
        if value.len() > BWS_KEYRING_BINDING_MAX_BYTES {
            delete_bws_binding_generation(store, generation, canonical.bindings.len()).await;
            return Err(SecretError::InvalidConfig(
                "BWS keyring binding is too large".to_string(),
            ));
        }
        let key = bws_binding_record_key(generation, index);
        if let Err(error) = store.set_secret(&key, &value, None).await {
            delete_bws_binding_generation(store, generation, canonical.bindings.len()).await;
            return Err(error);
        }
        match store.get_secret(&key).await {
            Ok(stored) if stored == value => {}
            Ok(_) | Err(_) => {
                delete_bws_binding_generation(store, generation, canonical.bindings.len()).await;
                return Err(SecretError::InvalidConfig(
                    "BWS keyring binding verification failed".to_string(),
                ));
            }
        }
    }

    let digest = bws_bindings_digest(&canonical.bindings)?;
    let root = StoredBwsKeyringRoot {
        schema_version: BWS_KEYRING_SCHEMA_VERSION,
        access_token: Zeroizing::new(canonical.access_token.to_string()),
        project_id: canonical.project_id.clone(),
        generation,
        binding_count: canonical.bindings.len(),
        bindings_sha256: encode_digest(&digest),
    };
    let mut root_writer = BoundedZeroizingJsonBuffer::new(BWS_KEYRING_ROOT_MAX_BYTES);
    if serde_json::to_writer(&mut root_writer, &root).is_err() {
        delete_bws_binding_generation(store, generation, canonical.bindings.len()).await;
        return Err(SecretError::InvalidConfig(
            "BWS keyring root is invalid".to_string(),
        ));
    }
    let root_value = root_writer.into_inner();
    let root_text = std::str::from_utf8(root_value.as_slice())
        .map_err(|_| SecretError::InvalidConfig("BWS keyring root is invalid".to_string()))?;
    if root_value.len() > WINDOWS_CREDENTIAL_BLOB_MAX_BYTES {
        delete_bws_binding_generation(store, generation, canonical.bindings.len()).await;
        return Err(SecretError::InvalidConfig(
            "BWS keyring root is too large".to_string(),
        ));
    }
    if let Err(error) = store
        .set_secret(PROVIDER_BWS_CONFIG_KEY, root_text, None)
        .await
    {
        delete_bws_binding_generation(store, generation, canonical.bindings.len()).await;
        return Err(error);
    }

    let verified = load_bws_keyring_config_inner(store).await;
    if !matches!(verified.as_ref(), Ok(Some(loaded)) if configs_match(loaded, &canonical)) {
        let restored = match old_root_value.as_deref() {
            Some(old_root) => {
                store
                    .set_secret(PROVIDER_BWS_CONFIG_KEY, old_root, None)
                    .await
            }
            None => store.delete_secret(PROVIDER_BWS_CONFIG_KEY).await,
        };
        if restored.is_err() {
            let _ = store.delete_secret(PROVIDER_BWS_CONFIG_KEY).await;
        }
        delete_bws_binding_generation(store, generation, canonical.bindings.len()).await;
        return Err(SecretError::InvalidConfig(
            "BWS keyring commit verification failed".to_string(),
        ));
    }

    if let Some((old_generation, old_count)) = old_root_metadata {
        if old_generation != generation {
            delete_bws_binding_generation(store, old_generation, old_count).await;
        }
    }
    Ok(())
}

async fn store_bws_keyring_config_with_generation(
    store: &dyn SecretVaultProvider,
    config: &BwsKeyringConfig,
    generation: Uuid,
) -> Result<(), SecretError> {
    let _guard = bws_keyring_transaction_lock().lock().await;
    store_bws_keyring_config_inner(store, config, generation).await
}

pub async fn store_bws_keyring_config(
    store: &dyn SecretVaultProvider,
    config: &BwsKeyringConfig,
) -> Result<(), SecretError> {
    store_bws_keyring_config_with_generation(store, config, Uuid::new_v4()).await
}

pub async fn clear_bws_keyring_config(store: &dyn SecretVaultProvider) -> Result<(), SecretError> {
    let _guard = bws_keyring_transaction_lock().lock().await;
    let root_value = match store.get_secret(PROVIDER_BWS_CONFIG_KEY).await {
        Ok(value) => Zeroizing::new(value),
        Err(SecretError::NotFound(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    let metadata = parse_stored_bws_root(root_value.as_str())
        .ok()
        .map(|root| (root.generation, root.binding_count));
    store.delete_secret(PROVIDER_BWS_CONFIG_KEY).await?;
    if let Some((generation, count)) = metadata {
        delete_bws_binding_generation(store, generation, count).await;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretBackendKind {
    #[default]
    OsKeyring,
    Bws,
    LocalAirGapped,
}

impl SecretBackendKind {
    pub fn parse(value: Option<&str>) -> Result<Self, SecretError> {
        match value {
            None | Some("os_keyring") => Ok(Self::OsKeyring),
            Some("bws") => Ok(Self::Bws),
            Some("local_air_gapped") => Ok(Self::LocalAirGapped),
            Some(_) => Err(SecretError::InvalidConfig(
                "unknown secret backend preference".to_string(),
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OsKeyring => "os_keyring",
            Self::Bws => "bws",
            Self::LocalAirGapped => "local_air_gapped",
        }
    }
}

/// Resolve the provider selected in the shared OS-keyring configuration.
/// Secret material stays in the keyring and is never written to app config.
pub async fn configured_secret_vault() -> Result<Arc<dyn SecretVaultProvider>, SecretError> {
    let config = OsKeyringVault::new(PROVIDER_CONFIG_SERVICE);
    let backend = match config.get_secret(PROVIDER_BACKEND_KEY).await {
        Ok(value) => SecretBackendKind::parse(Some(&value))?,
        Err(SecretError::NotFound(_)) => SecretBackendKind::OsKeyring,
        Err(error) => return Err(error),
    };
    match backend {
        SecretBackendKind::OsKeyring => Ok(Arc::new(OsKeyringVault::new("buzz-agent-vault"))),
        SecretBackendKind::LocalAirGapped => {
            Ok(Arc::new(OsKeyringVault::new("buzz-agent-vault-air-gapped")))
        }
        SecretBackendKind::Bws => {
            let stored = load_bws_keyring_config(&config).await?.ok_or_else(|| {
                SecretError::InvalidConfig("BWS access token is not configured".to_string())
            })?;
            Ok(Arc::new(
                BwsVault::from_zeroizing(Some(stored.access_token))
                    .with_project_id(Some(stored.project_id))
                    .with_bindings(&stored.bindings)?,
            ))
        }
    }
}

#[cfg(feature = "os-keyring")]
pub mod keyring_provider {
    use super::*;

    pub struct OsKeyringVault {
        service_name: String,
    }

    impl OsKeyringVault {
        pub fn new(service_name: impl Into<String>) -> Self {
            Self {
                service_name: service_name.into(),
            }
        }
    }

    #[async_trait]
    impl SecretVaultProvider for OsKeyringVault {
        fn name(&self) -> &str {
            "os-keyring"
        }

        async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
            let service = self.service_name.clone();
            let key_str = key.to_string();
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &key_str).map_err(|e| {
                    SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: e.to_string(),
                    }
                })?;
                entry.get_password().map_err(|e| match e {
                    keyring::Error::NoEntry => SecretError::NotFound(key_str),
                    other => SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: other.to_string(),
                    },
                })
            })
            .await
            .map_err(|e| SecretError::ProviderError {
                provider: "os-keyring".to_string(),
                message: format!("Blocking task join error: {}", e),
            })?
        }

        async fn set_secret(
            &self,
            key: &str,
            value: &str,
            _description: Option<&str>,
        ) -> Result<(), SecretError> {
            let service = self.service_name.clone();
            let key_str = key.to_string();
            let val_str = Zeroizing::new(value.to_string());
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &key_str).map_err(|e| {
                    SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: e.to_string(),
                    }
                })?;
                entry
                    .set_password(&val_str)
                    .map_err(|e| SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: e.to_string(),
                    })
            })
            .await
            .map_err(|e| SecretError::ProviderError {
                provider: "os-keyring".to_string(),
                message: format!("Blocking task join error: {}", e),
            })?
        }

        async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
            let service = self.service_name.clone();
            let key_str = key.to_string();
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &key_str).map_err(|e| {
                    SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: e.to_string(),
                    }
                })?;
                entry.delete_credential().map_err(|e| match e {
                    keyring::Error::NoEntry => SecretError::NotFound(key_str),
                    other => SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: other.to_string(),
                    },
                })
            })
            .await
            .map_err(|e| SecretError::ProviderError {
                provider: "os-keyring".to_string(),
                message: format!("Blocking task join error: {}", e),
            })?
        }

        async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError> {
            // Native OS keychains don't support listing keys across services portably without root/master prompts
            Ok(vec![])
        }
    }
}

pub mod bws_provider {
    use super::*;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

    const BWS_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
    const BWS_PIPE_OUTPUT_MAX_BYTES: usize = 1024 * 1024;
    const BWS_READ_SCRATCH_BYTES: usize = 8 * 1024;
    #[cfg(unix)]
    const BWS_SHELL: &str = "/bin/sh";
    #[cfg(unix)]
    const BWS_SHELL_BRIDGE: &str =
        "IFS= read -r BWS_ACCESS_TOKEN || exit 1\nexport BWS_ACCESS_TOKEN\nexec bws \"$@\"";
    #[cfg(windows)]
    const BWS_SHELL_BRIDGE: &str = "$bwsPath = [Console]::In.ReadLine(); $token = [Console]::In.ReadLine(); if ($null -eq $bwsPath -or $null -eq $token) { exit 1 }; $bwsArgs = @(); while (($line = [Console]::In.ReadLine()) -ne $null) { $bwsArgs += $line }; $env:BWS_ACCESS_TOKEN = $token; try { & $bwsPath @bwsArgs; exit $LASTEXITCODE } finally { Remove-Item Env:BWS_ACCESS_TOKEN -ErrorAction SilentlyContinue; $token = $null; $bwsPath = $null }";

    struct BwsCommandOutput {
        success: bool,
        stdout: Zeroizing<Vec<u8>>,
        _stderr: Zeroizing<Vec<u8>>,
    }

    #[derive(Deserialize)]
    struct BwsSecretRecord {
        id: Uuid,
        key: String,
        value: Zeroizing<String>,
        #[serde(rename = "projectId")]
        project_id: Option<Uuid>,
    }

    #[derive(Deserialize)]
    struct BwsProjectRecord {
        id: String,
    }

    /// Bitwarden Secrets Manager (BWS) CLI wrapper provider.
    pub struct BwsVault {
        access_token: Option<Zeroizing<String>>,
        project_id: Option<String>,
        bindings: BTreeMap<String, Uuid>,
    }

    fn provider_failure() -> SecretError {
        SecretError::ProviderError {
            provider: "bws".to_string(),
            message: "BWS command failed".to_string(),
        }
    }

    #[cfg(windows)]
    type BwsChild = Box<dyn process_wrap::tokio::ChildWrapper>;
    #[cfg(not(windows))]
    type BwsChild = tokio::process::Child;

    #[cfg(windows)]
    fn spawn_bws_command(command: tokio::process::Command) -> std::io::Result<BwsChild> {
        use process_wrap::tokio::{CommandWrap, JobObject, KillOnDrop};

        let mut command = CommandWrap::from(command);
        command.wrap(JobObject).wrap(KillOnDrop);
        command.spawn()
    }

    #[cfg(not(windows))]
    fn spawn_bws_command(mut command: tokio::process::Command) -> std::io::Result<BwsChild> {
        command.spawn()
    }

    #[cfg(windows)]
    fn take_child_stdin(child: &mut BwsChild) -> Option<tokio::process::ChildStdin> {
        child.stdin().take()
    }

    #[cfg(not(windows))]
    fn take_child_stdin(child: &mut BwsChild) -> Option<tokio::process::ChildStdin> {
        child.stdin.take()
    }

    #[cfg(windows)]
    fn take_child_stdout(child: &mut BwsChild) -> Option<tokio::process::ChildStdout> {
        child.stdout().take()
    }

    #[cfg(not(windows))]
    fn take_child_stdout(child: &mut BwsChild) -> Option<tokio::process::ChildStdout> {
        child.stdout.take()
    }

    #[cfg(windows)]
    fn take_child_stderr(child: &mut BwsChild) -> Option<tokio::process::ChildStderr> {
        child.stderr().take()
    }

    #[cfg(not(windows))]
    fn take_child_stderr(child: &mut BwsChild) -> Option<tokio::process::ChildStderr> {
        child.stderr.take()
    }

    #[cfg(windows)]
    struct BwsProcessTree;

    #[cfg(windows)]
    impl BwsProcessTree {
        fn attach(_child: &BwsChild) -> Result<Self, SecretError> {
            // `spawn_bws_command` uses process-wrap's JobObject wrapper, which
            // creates the process suspended and assigns it before resuming.
            Ok(Self)
        }

        fn terminate(&self) {}
    }

    #[cfg(unix)]
    struct BwsProcessTree {
        process_group: nix::unistd::Pid,
    }

    #[cfg(unix)]
    impl BwsProcessTree {
        fn attach(child: &BwsChild) -> Result<Self, SecretError> {
            let child_id = child.id().ok_or_else(provider_failure)?;
            let process_group = i32::try_from(child_id).map_err(|_| provider_failure())?;
            let process_group = nix::unistd::Pid::from_raw(process_group);
            if nix::unistd::getpgid(Some(process_group)) != Ok(process_group) {
                return Err(provider_failure());
            }
            Ok(Self { process_group })
        }

        fn terminate(&self) {
            let _ = nix::sys::signal::killpg(self.process_group, nix::sys::signal::Signal::SIGKILL);
        }
    }

    #[cfg(unix)]
    impl Drop for BwsProcessTree {
        fn drop(&mut self) {
            self.terminate();
        }
    }

    #[cfg(not(any(windows, unix)))]
    struct BwsProcessTree;

    #[cfg(not(any(windows, unix)))]
    impl BwsProcessTree {
        fn attach(_child: &BwsChild) -> Result<Self, SecretError> {
            Ok(Self)
        }

        fn terminate(&self) {}
    }

    type BwsReaderTask = tokio::task::JoinHandle<Result<Zeroizing<Vec<u8>>, SecretError>>;

    async fn read_bws_pipe<R>(
        mut pipe: R,
        mut output: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, SecretError>
    where
        R: AsyncRead + Unpin,
    {
        let mut scratch = Zeroizing::new([0_u8; BWS_READ_SCRATCH_BYTES]);
        loop {
            let read = pipe
                .read(&mut scratch[..])
                .await
                .map_err(|_| provider_failure())?;
            if read == 0 {
                return Ok(output);
            }
            if output.len().saturating_add(read) > BWS_PIPE_OUTPUT_MAX_BYTES {
                return Err(provider_failure());
            }
            output.extend_from_slice(&scratch[..read]);
        }
    }

    async fn abort_reader(task: &mut BwsReaderTask, pending: bool) {
        if pending {
            task.abort();
            let _ = task.await;
        }
    }

    async fn stop_bws_process(child: &mut BwsChild, process_tree: &BwsProcessTree) {
        process_tree.terminate();
        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    async fn terminate_bws_process(
        child: &mut BwsChild,
        process_tree: &BwsProcessTree,
        stdout_task: &mut BwsReaderTask,
        stdout_pending: bool,
        stderr_task: &mut BwsReaderTask,
        stderr_pending: bool,
    ) {
        stop_bws_process(child, process_tree).await;
        abort_reader(stdout_task, stdout_pending).await;
        abort_reader(stderr_task, stderr_pending).await;
    }

    async fn wait_for_bws_output(
        mut child: BwsChild,
        token_payload: Zeroizing<Vec<u8>>,
        timeout: Duration,
    ) -> Result<BwsCommandOutput, SecretError> {
        let process_tree = match BwsProcessTree::attach(&child) {
            Ok(process_tree) => process_tree,
            Err(error) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(error);
            }
        };
        let mut stdin = match take_child_stdin(&mut child) {
            Some(stdin) => stdin,
            None => {
                stop_bws_process(&mut child, &process_tree).await;
                return Err(provider_failure());
            }
        };
        let stdout = match take_child_stdout(&mut child) {
            Some(stdout) => stdout,
            None => {
                stop_bws_process(&mut child, &process_tree).await;
                return Err(provider_failure());
            }
        };
        let stderr = match take_child_stderr(&mut child) {
            Some(stderr) => stderr,
            None => {
                stop_bws_process(&mut child, &process_tree).await;
                return Err(provider_failure());
            }
        };
        let mut stdout_task = tokio::spawn(read_bws_pipe(
            stdout,
            Zeroizing::new(Vec::with_capacity(BWS_PIPE_OUTPUT_MAX_BYTES)),
        ));
        let mut stderr_task = tokio::spawn(read_bws_pipe(
            stderr,
            Zeroizing::new(Vec::with_capacity(BWS_PIPE_OUTPUT_MAX_BYTES)),
        ));
        let mut stdout_pending = true;
        let mut stderr_pending = true;
        let mut stdout_output = None;
        let mut stderr_output = None;
        let deadline = tokio::time::Instant::now() + timeout;

        let write_result =
            tokio::time::timeout_at(deadline, stdin.write_all(token_payload.as_slice())).await;
        if !matches!(write_result, Ok(Ok(()))) {
            terminate_bws_process(
                &mut child,
                &process_tree,
                &mut stdout_task,
                stdout_pending,
                &mut stderr_task,
                stderr_pending,
            )
            .await;
            return Err(provider_failure());
        }
        drop(stdin);

        let status = loop {
            tokio::select! {
                status = child.wait() => {
                    break match status {
                        Ok(status) => status,
                        Err(_) => {
                            terminate_bws_process(
                                &mut child,
                                &process_tree,
                                &mut stdout_task,
                                stdout_pending,
                                &mut stderr_task,
                                stderr_pending,
                            ).await;
                            return Err(provider_failure());
                        }
                    };
                }
                result = &mut stdout_task, if stdout_pending => {
                    stdout_pending = false;
                    match result {
                        Ok(Ok(output)) => stdout_output = Some(output),
                        _ => {
                            terminate_bws_process(
                                &mut child,
                                &process_tree,
                                &mut stdout_task,
                                stdout_pending,
                                &mut stderr_task,
                                stderr_pending,
                            ).await;
                            return Err(provider_failure());
                        }
                    }
                }
                result = &mut stderr_task, if stderr_pending => {
                    stderr_pending = false;
                    match result {
                        Ok(Ok(output)) => stderr_output = Some(output),
                        _ => {
                            terminate_bws_process(
                                &mut child,
                                &process_tree,
                                &mut stdout_task,
                                stdout_pending,
                                &mut stderr_task,
                                stderr_pending,
                            ).await;
                            return Err(provider_failure());
                        }
                    }
                }
                () = tokio::time::sleep_until(deadline) => {
                    terminate_bws_process(
                        &mut child,
                        &process_tree,
                        &mut stdout_task,
                        stdout_pending,
                        &mut stderr_task,
                        stderr_pending,
                    ).await;
                    return Err(provider_failure());
                }
            }
        };

        if stdout_pending {
            match tokio::time::timeout_at(deadline, &mut stdout_task).await {
                Ok(Ok(Ok(output))) => {
                    stdout_output = Some(output);
                }
                Ok(_) => {
                    terminate_bws_process(
                        &mut child,
                        &process_tree,
                        &mut stdout_task,
                        false,
                        &mut stderr_task,
                        stderr_pending,
                    )
                    .await;
                    return Err(provider_failure());
                }
                Err(_) => {
                    terminate_bws_process(
                        &mut child,
                        &process_tree,
                        &mut stdout_task,
                        true,
                        &mut stderr_task,
                        stderr_pending,
                    )
                    .await;
                    return Err(provider_failure());
                }
            }
        }
        if stderr_pending {
            match tokio::time::timeout_at(deadline, &mut stderr_task).await {
                Ok(Ok(Ok(output))) => {
                    stderr_output = Some(output);
                }
                Ok(_) => {
                    terminate_bws_process(
                        &mut child,
                        &process_tree,
                        &mut stdout_task,
                        false,
                        &mut stderr_task,
                        false,
                    )
                    .await;
                    return Err(provider_failure());
                }
                Err(_) => {
                    terminate_bws_process(
                        &mut child,
                        &process_tree,
                        &mut stdout_task,
                        false,
                        &mut stderr_task,
                        true,
                    )
                    .await;
                    return Err(provider_failure());
                }
            }
        }

        let stdout = match stdout_output {
            Some(stdout) => stdout,
            None => {
                terminate_bws_process(
                    &mut child,
                    &process_tree,
                    &mut stdout_task,
                    false,
                    &mut stderr_task,
                    false,
                )
                .await;
                return Err(provider_failure());
            }
        };
        let stderr = match stderr_output {
            Some(stderr) => stderr,
            None => {
                terminate_bws_process(
                    &mut child,
                    &process_tree,
                    &mut stdout_task,
                    false,
                    &mut stderr_task,
                    false,
                )
                .await;
                return Err(provider_failure());
            }
        };
        if !status.success() {
            terminate_bws_process(
                &mut child,
                &process_tree,
                &mut stdout_task,
                false,
                &mut stderr_task,
                false,
            )
            .await;
        }

        Ok(BwsCommandOutput {
            success: status.success(),
            stdout,
            _stderr: stderr,
        })
    }

    impl BwsVault {
        fn child_stdin_payload(
            token: &str,
            args: &[&str],
        ) -> Result<Zeroizing<Vec<u8>>, SecretError> {
            #[cfg(windows)]
            let bws_path = trusted_windows_bws_path().map_err(|_| provider_failure())?;
            #[cfg(windows)]
            let bws_path = bws_path.as_os_str().to_string_lossy();
            let mut payload = Zeroizing::new(Vec::with_capacity(
                token.len() + args.iter().map(|arg| arg.len() + 1).sum::<usize>() + 1 + {
                    #[cfg(windows)]
                    {
                        bws_path.len() + 1
                    }
                    #[cfg(not(windows))]
                    {
                        0
                    }
                },
            ));
            #[cfg(windows)]
            {
                payload.extend_from_slice(bws_path.as_bytes());
                payload.push(b'\n');
            }
            payload.extend_from_slice(token.as_bytes());
            payload.push(b'\n');
            #[cfg(windows)]
            for arg in args {
                payload.extend_from_slice(arg.as_bytes());
                payload.push(b'\n');
            }
            Ok(payload)
        }

        pub fn new(access_token: Option<String>) -> Self {
            Self::from_zeroizing(access_token.map(Zeroizing::new))
        }

        pub fn from_zeroizing(access_token: Option<Zeroizing<String>>) -> Self {
            Self {
                access_token,
                project_id: None,
                bindings: BTreeMap::new(),
            }
        }

        pub fn with_project_id(mut self, project_id: Option<String>) -> Self {
            self.project_id = project_id.filter(|id| !id.trim().is_empty());
            self
        }

        pub fn with_bindings(mut self, bindings: &[BwsSecretBinding]) -> Result<Self, SecretError> {
            self.bindings = validate_bws_secret_bindings(bindings)?;
            Ok(self)
        }

        fn required_project_id(&self) -> Result<Uuid, SecretError> {
            let project_id = self.project_id.as_deref().ok_or_else(|| {
                SecretError::InvalidConfig("BWS project scope is required".to_string())
            })?;
            Uuid::parse_str(project_id).map_err(|_| {
                SecretError::InvalidConfig("BWS project scope must be a UUID".to_string())
            })
        }

        fn get_token(&self) -> Result<Zeroizing<String>, SecretError> {
            let token = self
                .access_token
                .as_ref()
                .map(|token| Zeroizing::new(token.to_string()))
                .ok_or_else(|| {
                    SecretError::InvalidConfig(
                        "BWS access token is not configured in the OS credential vault".to_string(),
                    )
                })?;
            if token.len() < 20 || token.len() > 4096 || token.chars().any(char::is_whitespace) {
                return Err(SecretError::InvalidConfig(
                    "BWS access token format is invalid".to_string(),
                ));
            }
            Ok(token)
        }

        fn valid_command_args(args: &[&str]) -> bool {
            match args {
                ["project", "get", id, "--output", "json"]
                | ["secret", "get", id, "--output", "json"] => Uuid::parse_str(id).is_ok(),
                _ => false,
            }
        }

        fn command(&self, args: &[&str]) -> Result<tokio::process::Command, SecretError> {
            if !Self::valid_command_args(args) {
                return Err(SecretError::InvalidConfig(
                    "BWS command arguments are invalid".to_string(),
                ));
            }
            #[cfg(unix)]
            let mut command = tokio::process::Command::new(BWS_SHELL);
            #[cfg(windows)]
            let mut command = tokio::process::Command::new(
                trusted_windows_powershell_path().map_err(|_| provider_failure())?,
            );
            #[cfg(unix)]
            command
                .args(["-c", BWS_SHELL_BRIDGE, "buzz-bws-bridge"])
                .args(args);
            #[cfg(windows)]
            command.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                BWS_SHELL_BRIDGE,
            ]);
            command
                .env_remove("BWS_ACCESS_TOKEN")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.as_std_mut().process_group(0);
            }
            Ok(command)
        }

        async fn run_bws(&self, args: &[&str]) -> Result<BwsCommandOutput, SecretError> {
            let token = self.get_token()?;
            let token_payload = Self::child_stdin_payload(token.as_str(), args)?;
            drop(token);
            let child = spawn_bws_command(self.command(args)?).map_err(|_| provider_failure())?;
            wait_for_bws_output(child, token_payload, BWS_COMMAND_TIMEOUT).await
        }

        fn parse_secret_response(
            &self,
            expected_secret_id: Uuid,
            expected_key: &str,
            stdout: &[u8],
        ) -> Result<String, SecretError> {
            let mut record: BwsSecretRecord =
                serde_json::from_slice(stdout).map_err(|_| provider_failure())?;
            let expected_project = self.required_project_id()?;
            if record.project_id != Some(expected_project)
                || record.id != expected_secret_id
                || record.key != expected_key
            {
                return Err(provider_failure());
            }
            Ok(std::mem::take(&mut *record.value))
        }

        /// Verify authentication and configured project scope without requesting
        /// any secret records or values from BWS.
        pub async fn test_connection(&self) -> Result<(), SecretError> {
            let expected_project = self.required_project_id()?;
            let project_arg = expected_project.to_string();
            let output = self
                .run_bws(&["project", "get", &project_arg, "--output", "json"])
                .await?;
            if !output.success {
                return Err(provider_failure());
            }
            let record: BwsProjectRecord =
                serde_json::from_slice(output.stdout.as_slice()).map_err(|_| provider_failure())?;
            if Uuid::parse_str(&record.id).ok() != Some(expected_project) {
                return Err(provider_failure());
            }
            Ok(())
        }
    }

    #[async_trait]
    impl SecretVaultProvider for BwsVault {
        fn name(&self) -> &str {
            "bws"
        }

        async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
            self.required_project_id()?;
            let secret_id = self
                .bindings
                .get(key)
                .copied()
                .ok_or_else(|| SecretError::NotFound(key.to_string()))?;
            let secret_id_arg = secret_id.to_string();
            let get_output = self
                .run_bws(&["secret", "get", &secret_id_arg, "--output", "json"])
                .await?;
            if !get_output.success {
                return Err(provider_failure());
            }
            self.parse_secret_response(secret_id, key, get_output.stdout.as_slice())
        }

        async fn set_secret(
            &self,
            _key: &str,
            _value: &str,
            _description: Option<&str>,
        ) -> Result<(), SecretError> {
            Err(SecretError::ProviderError {
                provider: "bws".to_string(),
                message: "Creating/Updating BWS secrets via CLI requires project_id and is disabled for agent safety".to_string(),
            })
        }

        async fn delete_secret(&self, _key: &str) -> Result<(), SecretError> {
            Err(SecretError::ProviderError {
                provider: "bws".to_string(),
                message: "Deleting BWS secrets via agent is disabled for safety".to_string(),
            })
        }

        async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError> {
            Ok(self
                .bindings
                .keys()
                .map(|key| SecretMetadata {
                    key: key.clone(),
                    description: None,
                    provider: "bws".to_string(),
                    updated_at: Utc::now(),
                })
                .collect())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[cfg(unix)]
        fn configure_unix_test_process_group(command: &mut tokio::process::Command) {
            use std::os::unix::process::CommandExt;
            command.as_std_mut().process_group(0);
        }

        #[test]
        fn access_token_is_delivered_only_over_child_stdin() {
            let vault = BwsVault::new(Some("test-machine-token-1234".to_string()));
            let command = vault
                .command(&[
                    "project",
                    "get",
                    "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135",
                    "--output",
                    "json",
                ])
                .expect("command");
            let command = command.as_std();
            let args: Vec<_> = command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            assert!(!args
                .iter()
                .any(|arg| arg.contains("test-machine-token-1234")));
            let token_env = command
                .get_envs()
                .find(|(key, _)| *key == "BWS_ACCESS_TOKEN")
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned());
            assert_eq!(token_env, None);
            #[cfg(windows)]
            {
                let payload = BwsVault::child_stdin_payload(
                    "test-machine-token-1234",
                    &[
                        "project",
                        "get",
                        "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135",
                        "--output",
                        "json",
                    ],
                )
                .expect("trusted absolute BWS path");
                let first_line = payload
                    .split(|byte| *byte == b'\n')
                    .next()
                    .expect("BWS path line");
                let expected = trusted_windows_bws_path().expect("installed BWS");
                assert_eq!(
                    first_line,
                    expected.as_os_str().to_string_lossy().as_bytes()
                );
                assert!(expected.is_absolute());
            }
            assert!(!BwsVault::valid_command_args(&[
                "project", "list", "--output", "json"
            ]));
            assert!(!BwsVault::valid_command_args(&[
                "secret",
                "get",
                "logical-key",
                "--output",
                "json"
            ]));
            assert!(!BwsVault::valid_command_args(&[
                "secret",
                "list",
                "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135",
                "--output",
                "json"
            ]));
        }

        #[test]
        fn durable_bindings_reject_malformed_duplicate_and_over_cap_entries() {
            let binding = |logical_key: &str, secret_id: &str| BwsSecretBinding {
                logical_key: logical_key.to_string(),
                secret_id: secret_id.to_string(),
            };
            let first_id = "bd34a60b-f794-46fb-8aa5-97fdd96e69b1";
            let second_id = "dc0e31b7-7492-4438-b9ed-45ff18b8da64";

            for invalid in [
                vec![binding("", first_id)],
                vec![binding("   ", first_id)],
                vec![binding("line\nbreak", first_id)],
                vec![binding(&"x".repeat(257), first_id)],
                vec![binding("logical-key", "not-a-uuid")],
                vec![
                    binding("logical-key", first_id),
                    binding("logical-key", second_id),
                ],
                vec![binding("one", first_id), binding("two", first_id)],
            ] {
                assert!(validate_bws_secret_bindings(&invalid).is_err());
            }

            let over_cap = (0..=MAX_BWS_SECRET_BINDINGS)
                .map(|index| binding(&format!("key-{index}"), &Uuid::new_v4().to_string()))
                .collect::<Vec<_>>();
            assert!(validate_bws_secret_bindings(&over_cap).is_err());
        }

        #[test]
        fn durable_bindings_preserve_exact_keys_and_canonicalize_uuids() {
            let bindings = vec![BwsSecretBinding {
                logical_key: " Exact logical key ".to_string(),
                secret_id: "BD34A60B-F794-46FB-8AA5-97FDD96E69B1".to_string(),
            }];

            let validated = validate_bws_secret_bindings(&bindings).unwrap();
            assert_eq!(
                validated.get(" Exact logical key "),
                Some(&Uuid::parse_str("bd34a60b-f794-46fb-8aa5-97fdd96e69b1").unwrap())
            );
            assert!(!validated.contains_key("Exact logical key"));
        }

        #[cfg(windows)]
        #[tokio::test]
        async fn substituted_windows_powershell_cannot_consume_post_assignment_stdin() {
            let temp = std::env::temp_dir()
                .join(format!("buzz-bws-substituted-launcher-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&temp).unwrap();
            let source = temp.join("substituted_launcher.rs");
            let launcher = temp.join("powershell.exe");
            let marker = temp.join("substituted-launcher-ran");
            std::fs::write(
                &source,
                r#"use std::io::Read;
fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    std::fs::write(
        std::env::var_os("BUZZ_SUBSTITUTED_LAUNCHER_MARKER").unwrap(),
        input,
    )
    .unwrap();
}
"#,
            )
            .unwrap();
            let compiled = std::process::Command::new("rustc")
                .args([source.as_os_str(), "-o".as_ref(), launcher.as_os_str()])
                .status()
                .unwrap();
            assert!(compiled.success(), "failed to compile launcher fixture");

            let vault = BwsVault::new(Some("post-assignment-fixture".to_string()));
            let args = [
                "project",
                "get",
                "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135",
                "--output",
                "json",
            ];
            let mut command = vault.command(&args).unwrap();
            let path = std::env::var_os("PATH").unwrap_or_default();
            command
                .current_dir(&temp)
                .env(
                    "PATH",
                    std::env::join_paths([temp.as_os_str(), path.as_os_str()]).unwrap(),
                )
                .env("BUZZ_SUBSTITUTED_LAUNCHER_MARKER", &marker);
            let child = spawn_bws_command(command).unwrap();
            let _ = wait_for_bws_output(
                child,
                BwsVault::child_stdin_payload("post-assignment-fixture", &args).unwrap(),
                Duration::from_secs(3),
            )
            .await;

            assert!(
                !marker.exists(),
                "a current-directory or PATH powershell substitute consumed bridge stdin"
            );
            let _ = std::fs::remove_dir_all(temp);
        }

        #[tokio::test]
        async fn subprocess_wait_has_a_short_hard_timeout_and_generic_error() {
            #[cfg(windows)]
            let mut command = {
                let mut command = tokio::process::Command::new("powershell.exe");
                command.args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 2",
                ]);
                command
            };
            #[cfg(unix)]
            let mut command = {
                let mut command = tokio::process::Command::new("sh");
                command.args(["-c", "sleep 2"]);
                command
            };
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            #[cfg(unix)]
            configure_unix_test_process_group(&mut command);
            let child = spawn_bws_command(command).unwrap();
            let started = std::time::Instant::now();
            let error = match wait_for_bws_output(
                child,
                Zeroizing::new(b"test-machine-token-1234".to_vec()),
                Duration::from_millis(25),
            )
            .await
            {
                Err(error) => error,
                Ok(_) => panic!("slow child unexpectedly completed"),
            };
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(
                error.to_string(),
                "Provider error (bws): BWS command failed"
            );
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn bws_command_launches_in_a_private_unix_process_group() {
            let vault = BwsVault::new(Some("test-machine-token-1234".to_string()));
            let mut child = vault
                .command(&[
                    "project",
                    "get",
                    "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135",
                    "--output",
                    "json",
                ])
                .unwrap()
                .spawn()
                .unwrap();
            let process_tree = BwsProcessTree::attach(&child).unwrap();

            assert_eq!(
                nix::unistd::getpgid(Some(process_tree.process_group)),
                Ok(process_tree.process_group)
            );
            stop_bws_process(&mut child, &process_tree).await;
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn timeout_kills_unix_descendants_before_they_can_write_a_marker() {
            let marker =
                std::env::temp_dir().join(format!("buzz-bws-unix-tree-{}.txt", Uuid::new_v4()));
            let mut command = tokio::process::Command::new("/bin/sh");
            command
                .args([
                    "-c",
                    "(sleep 0.4; printf marker > \"$1\") & sleep 30",
                    "buzz-bws-tree-test",
                ])
                .arg(&marker)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            configure_unix_test_process_group(&mut command);
            let child = spawn_bws_command(command).unwrap();

            let result = wait_for_bws_output(
                child,
                Zeroizing::new(b"test-machine-token-1234".to_vec()),
                Duration::from_millis(75),
            )
            .await;

            assert!(result.is_err(), "process tree must time out");
            tokio::time::sleep(Duration::from_millis(700)).await;
            assert!(!marker.exists(), "descendant survived the timeout");
            let _ = std::fs::remove_file(marker);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn inherited_unix_pipe_timeout_is_bounded_and_kills_the_holder() {
            let marker =
                std::env::temp_dir().join(format!("buzz-bws-unix-pipe-{}.txt", Uuid::new_v4()));
            let mut command = tokio::process::Command::new("/bin/sh");
            command
                .args([
                    "-c",
                    "(sleep 0.4; printf marker > \"$1\") & exit 0",
                    "buzz-bws-pipe-test",
                ])
                .arg(&marker)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            configure_unix_test_process_group(&mut command);
            let child = spawn_bws_command(command).unwrap();
            let started = std::time::Instant::now();

            let result = wait_for_bws_output(
                child,
                Zeroizing::new(b"test-machine-token-1234".to_vec()),
                Duration::from_millis(75),
            )
            .await;

            assert!(result.is_err(), "inherited pipes must hit the hard timeout");
            assert!(
                started.elapsed() < Duration::from_millis(500),
                "pipe holder made completion exceed the bounded timeout"
            );
            tokio::time::sleep(Duration::from_millis(700)).await;
            assert!(!marker.exists(), "inherited-pipe holder survived timeout");
            let _ = std::fs::remove_file(marker);
        }

        #[tokio::test]
        async fn subprocess_output_is_explicitly_capped_with_a_generic_error() {
            #[cfg(windows)]
            let mut command = {
                let mut command = tokio::process::Command::new("powershell.exe");
                command.args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "[Console]::Out.Write('x' * 1048577)",
                ]);
                command
            };
            #[cfg(unix)]
            let mut command = {
                let mut command = tokio::process::Command::new("sh");
                command.args(["-c", "yes x | head -c 1048577"]);
                command
            };
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            #[cfg(unix)]
            configure_unix_test_process_group(&mut command);
            let child = spawn_bws_command(command).unwrap();
            let result = wait_for_bws_output(
                child,
                Zeroizing::new(b"test-machine-token-1234".to_vec()),
                Duration::from_secs(3),
            )
            .await;
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("oversized output must fail closed"),
            };
            assert_eq!(
                error.to_string(),
                "Provider error (bws): BWS command failed"
            );
        }

        #[cfg(windows)]
        #[tokio::test]
        async fn timeout_kills_descendants_before_they_can_write_a_marker() {
            let marker = std::env::temp_dir().join(format!("buzz-bws-tree-{}.txt", Uuid::new_v4()));
            let script = std::env::temp_dir().join(format!("buzz-bws-tree-{}.ps1", Uuid::new_v4()));
            std::fs::write(
                &script,
                format!(
                    "Start-Sleep -Milliseconds 500; [IO.File]::WriteAllText('{}', 'marker')",
                    marker.display().to_string().replace('\'', "''")
                ),
            )
            .unwrap();
            let parent_script = format!(
                "Start-Process powershell.exe -ArgumentList '-NoProfile','-File','{}'; Start-Sleep -Seconds 30",
                script.display().to_string().replace('\'', "''")
            );
            let mut command = tokio::process::Command::new("powershell.exe");
            command
                .args(["-NoProfile", "-NonInteractive", "-Command", &parent_script])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            let child = spawn_bws_command(command).unwrap();
            let result = wait_for_bws_output(
                child,
                Zeroizing::new(b"test-machine-token-1234".to_vec()),
                Duration::from_millis(75),
            )
            .await;
            assert!(result.is_err(), "process tree must time out");
            tokio::time::sleep(Duration::from_millis(900)).await;
            assert!(!marker.exists(), "descendant survived the timeout");
            let _ = std::fs::remove_file(marker);
            let _ = std::fs::remove_file(script);
        }

        #[test]
        fn logical_key_resolution_uses_only_the_durable_binding() {
            let vault = BwsVault::new(Some("test-machine-token-1234".to_string()))
                .with_project_id(Some("8B7B9142-F5C1-4A7A-A9FA-179C3BE1B135".to_string()))
                .with_bindings(&[BwsSecretBinding {
                    logical_key: "logical-key".to_string(),
                    secret_id: "BD34A60B-F794-46FB-8AA5-97FDD96E69B1".to_string(),
                }])
                .unwrap();
            assert_eq!(
                vault.bindings.get("logical-key"),
                Some(&Uuid::parse_str("bd34a60b-f794-46fb-8aa5-97fdd96e69b1").unwrap())
            );
            assert!(!vault.bindings.contains_key("Logical-Key"));
        }

        #[test]
        fn secret_get_response_requires_resolved_uuid_and_exact_logical_key() {
            let vault = BwsVault::new(Some("test-machine-token-1234".to_string()))
                .with_project_id(Some("8B7B9142-F5C1-4A7A-A9FA-179C3BE1B135".to_string()));
            let expected_secret_id =
                Uuid::parse_str("bd34a60b-f794-46fb-8aa5-97fdd96e69b1").unwrap();
            let wrong_secret_id = br#"{"id":"dc0e31b7-7492-4438-b9ed-45ff18b8da64","key":"logical-key","value":"must-not-return","projectId":"8b7b9142-f5c1-4a7a-a9fa-179c3be1b135"}"#;
            let wrong_exact_key = br#"{"id":"bd34a60b-f794-46fb-8aa5-97fdd96e69b1","key":"Logical-Key","value":"must-not-return","projectId":"8b7b9142-f5c1-4a7a-a9fa-179c3be1b135"}"#;

            for response in [wrong_secret_id.as_slice(), wrong_exact_key.as_slice()] {
                let error = vault
                    .parse_secret_response(expected_secret_id, "logical-key", response)
                    .expect_err("substituted same-project response must fail closed");
                assert_eq!(
                    error.to_string(),
                    "Provider error (bws): BWS command failed"
                );
                assert!(!error.to_string().contains("must-not-return"));
            }

            let semantically_equivalent_uuid_spelling = br#"{"id":"BD34A60B-F794-46FB-8AA5-97FDD96E69B1","key":"logical-key","value":"fixture-value","projectId":"8b7b9142-f5c1-4a7a-a9fa-179c3be1b135"}"#;
            assert_eq!(
                vault
                    .parse_secret_response(
                        expected_secret_id,
                        "logical-key",
                        semantically_equivalent_uuid_spelling,
                    )
                    .unwrap(),
                "fixture-value"
            );
        }

        #[test]
        fn project_scope_is_required_before_returning_a_secret_value() {
            let vault = BwsVault::new(Some("test-machine-token-1234".to_string()))
                .with_project_id(Some("8b7b9142-f5c1-4a7a-a9fa-179c3be1b135".to_string()));
            let expected_secret_id =
                Uuid::parse_str("bd34a60b-f794-46fb-8aa5-97fdd96e69b1").unwrap();
            let matching = br#"{"id":"bd34a60b-f794-46fb-8aa5-97fdd96e69b1","key":"logical-key","value":"fixture-value","projectId":"8b7b9142-f5c1-4a7a-a9fa-179c3be1b135"}"#;
            assert_eq!(
                vault
                    .parse_secret_response(expected_secret_id, "logical-key", matching)
                    .unwrap(),
                "fixture-value"
            );
            let mismatched = br#"{"id":"bd34a60b-f794-46fb-8aa5-97fdd96e69b1","key":"logical-key","value":"fixture-value","projectId":"914d7d7b-00f8-471c-8cb4-2ec3672d05e9"}"#;
            assert!(matches!(
                vault.parse_secret_response(expected_secret_id, "logical-key", mismatched),
                Err(SecretError::ProviderError { .. })
            ));
            let missing_scope = br#"{"id":"bd34a60b-f794-46fb-8aa5-97fdd96e69b1","key":"logical-key","value":"fixture-value"}"#;
            assert!(matches!(
                vault.parse_secret_response(expected_secret_id, "logical-key", missing_scope),
                Err(SecretError::ProviderError { .. })
            ));
            assert!(vault
                .parse_secret_response(expected_secret_id, "logical-key", b"not-json")
                .is_err());
        }

        #[test]
        fn project_scope_compares_uuid_values_not_spelling() {
            let vault = BwsVault::new(Some("test-machine-token-1234".to_string()))
                .with_project_id(Some("8B7B9142-F5C1-4A7A-A9FA-179C3BE1B135".to_string()));
            let expected_secret_id =
                Uuid::parse_str("bd34a60b-f794-46fb-8aa5-97fdd96e69b1").unwrap();
            let response = br#"{"id":"bd34a60b-f794-46fb-8aa5-97fdd96e69b1","key":"logical-key","value":"fixture-value","projectId":"8b7b9142-f5c1-4a7a-a9fa-179c3be1b135"}"#;

            assert_eq!(
                vault
                    .parse_secret_response(expected_secret_id, "logical-key", response)
                    .unwrap(),
                "fixture-value"
            );
        }

        #[tokio::test]
        async fn invalid_or_missing_project_scope_fails_before_spawning_bws() {
            for project_id in [None, Some("not-a-uuid".to_string())] {
                let vault = BwsVault::new(Some("test-machine-token-1234".to_string()))
                    .with_project_id(project_id);
                assert!(matches!(
                    vault.get_secret("secret-id").await,
                    Err(SecretError::InvalidConfig(_))
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct TransactionTestStore {
        state: Mutex<TransactionTestState>,
    }

    #[derive(Default)]
    struct TransactionTestState {
        entries: BTreeMap<String, String>,
        operations: Vec<String>,
        fail_set_key: Option<String>,
        fail_delete_key: Option<String>,
    }

    impl TransactionTestStore {
        fn entry(&self, key: &str) -> Option<String> {
            self.state.lock().unwrap().entries.get(key).cloned()
        }

        fn insert(&self, key: impl Into<String>, value: impl Into<String>) {
            self.state
                .lock()
                .unwrap()
                .entries
                .insert(key.into(), value.into());
        }

        fn remove(&self, key: &str) {
            self.state.lock().unwrap().entries.remove(key);
        }

        fn entries(&self) -> BTreeMap<String, String> {
            self.state.lock().unwrap().entries.clone()
        }

        fn operations(&self) -> Vec<String> {
            self.state.lock().unwrap().operations.clone()
        }

        fn clear_operations(&self) {
            self.state.lock().unwrap().operations.clear();
        }

        fn fail_set(&self, key: impl Into<String>) {
            self.state.lock().unwrap().fail_set_key = Some(key.into());
        }

        fn fail_delete(&self, key: impl Into<String>) {
            self.state.lock().unwrap().fail_delete_key = Some(key.into());
        }
    }

    #[async_trait]
    impl SecretVaultProvider for TransactionTestStore {
        fn name(&self) -> &str {
            "transaction-test-store"
        }

        async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
            let mut state = self.state.lock().unwrap();
            state.operations.push(format!("get:{key}"));
            state
                .entries
                .get(key)
                .cloned()
                .ok_or_else(|| SecretError::NotFound(key.to_string()))
        }

        async fn set_secret(
            &self,
            key: &str,
            value: &str,
            _description: Option<&str>,
        ) -> Result<(), SecretError> {
            let mut state = self.state.lock().unwrap();
            state.operations.push(format!("set:{key}"));
            if state.fail_set_key.as_deref() == Some(key) {
                return Err(SecretError::ProviderError {
                    provider: "transaction-test-store".to_string(),
                    message: "injected write failure".to_string(),
                });
            }
            state.entries.insert(key.to_string(), value.to_string());
            Ok(())
        }

        async fn delete_secret(&self, key: &str) -> Result<(), SecretError> {
            let mut state = self.state.lock().unwrap();
            state.operations.push(format!("delete:{key}"));
            if state.fail_delete_key.as_deref() == Some(key) {
                return Err(SecretError::ProviderError {
                    provider: "transaction-test-store".to_string(),
                    message: "injected delete failure".to_string(),
                });
            }
            state
                .entries
                .remove(key)
                .map(|_| ())
                .ok_or_else(|| SecretError::NotFound(key.to_string()))
        }

        async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError> {
            panic!("BWS keyring transactions must never enumerate credentials")
        }
    }

    fn transaction_binding(index: usize, long: bool) -> BwsSecretBinding {
        let logical_key = if long {
            format!("{index:03}-{}", "x".repeat(MAX_BWS_LOGICAL_KEY_BYTES - 4))
        } else {
            format!("logical-key-{index:03}")
        };
        BwsSecretBinding {
            logical_key,
            secret_id: Uuid::from_u128(index as u128 + 1).to_string(),
        }
    }

    fn transaction_config(count: usize, long: bool) -> BwsKeyringConfig {
        BwsKeyringConfig::new(
            Zeroizing::new("t".repeat(MAX_BWS_ACCESS_TOKEN_BYTES)),
            "8B7B9142-F5C1-4A7A-A9FA-179C3BE1B135".to_string(),
            (0..count)
                .map(|index| transaction_binding(index, long))
                .collect(),
        )
        .unwrap()
    }

    async fn stored_generation(store: &TransactionTestStore) -> Uuid {
        let root = store.entry(PROVIDER_BWS_CONFIG_KEY).unwrap();
        serde_json::from_str::<StoredBwsKeyringRoot>(&root)
            .unwrap()
            .generation
    }

    #[tokio::test]
    async fn bws_keyring_transaction_supports_128_long_bindings_beyond_legacy_blob_capacity() {
        let config = transaction_config(MAX_BWS_SECRET_BINDINGS, true);
        let legacy = serde_json::to_vec(&serde_json::json!({
            "access_token": config.access_token.as_str(),
            "project_id": config.project_id,
            "bindings": config.bindings,
        }))
        .unwrap();
        assert!(legacy.len() > WINDOWS_CREDENTIAL_BLOB_MAX_BYTES);

        let store = TransactionTestStore::default();
        store_bws_keyring_config(&store, &config).await.unwrap();
        let entries = store.entries();
        assert_eq!(entries.len(), MAX_BWS_SECRET_BINDINGS + 1);
        assert!(entries[PROVIDER_BWS_CONFIG_KEY].len() <= BWS_KEYRING_ROOT_MAX_BYTES);
        for (key, value) in &entries {
            if key != PROVIDER_BWS_CONFIG_KEY {
                assert!(value.len() <= BWS_KEYRING_BINDING_MAX_BYTES);
            }
        }
        let loaded = load_bws_keyring_config(&store).await.unwrap().unwrap();
        assert_eq!(loaded.bindings.len(), MAX_BWS_SECRET_BINDINGS);
        assert_eq!(loaded.project_id, "8b7b9142-f5c1-4a7a-a9fa-179c3be1b135");
    }

    #[tokio::test]
    async fn bws_keyring_precommit_item_failure_preserves_old_root() {
        let store = TransactionTestStore::default();
        store_bws_keyring_config(&store, &transaction_config(2, false))
            .await
            .unwrap();
        let old_root = store.entry(PROVIDER_BWS_CONFIG_KEY).unwrap();
        store.clear_operations();
        store.fail_set(bws_binding_record_key(Uuid::nil(), 1));

        let result = store_bws_keyring_config_with_generation(
            &store,
            &transaction_config(3, false),
            Uuid::nil(),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(store.entry(PROVIDER_BWS_CONFIG_KEY).unwrap(), old_root);
        assert!(!store
            .entries()
            .keys()
            .any(|key| key.starts_with(&bws_binding_generation_prefix(Uuid::nil()))));
    }

    #[tokio::test]
    async fn bws_keyring_root_write_failure_preserves_old_root() {
        let store = TransactionTestStore::default();
        store_bws_keyring_config(&store, &transaction_config(2, false))
            .await
            .unwrap();
        let old_root = store.entry(PROVIDER_BWS_CONFIG_KEY).unwrap();
        store.clear_operations();
        store.fail_set(PROVIDER_BWS_CONFIG_KEY);

        let result = store_bws_keyring_config_with_generation(
            &store,
            &transaction_config(3, false),
            Uuid::nil(),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(store.entry(PROVIDER_BWS_CONFIG_KEY).unwrap(), old_root);
        assert!(!store
            .entries()
            .keys()
            .any(|key| key.starts_with(&bws_binding_generation_prefix(Uuid::nil()))));
    }

    #[tokio::test]
    async fn bws_keyring_load_rejects_missing_corrupt_mismatched_and_duplicate_items() {
        for mutation in 0..4 {
            let store = TransactionTestStore::default();
            store_bws_keyring_config(&store, &transaction_config(2, false))
                .await
                .unwrap();
            let generation = stored_generation(&store).await;
            let first_key = bws_binding_record_key(generation, 0);
            match mutation {
                0 => store.remove(&first_key),
                1 => store.insert(&first_key, "not-json"),
                2 => {
                    let mut item: StoredBwsKeyringBinding =
                        serde_json::from_str(&store.entry(&first_key).unwrap()).unwrap();
                    item.index = 1;
                    store.insert(&first_key, serde_json::to_string(&item).unwrap());
                }
                3 => {
                    let second_key = bws_binding_record_key(generation, 1);
                    let mut second: StoredBwsKeyringBinding =
                        serde_json::from_str(&store.entry(&second_key).unwrap()).unwrap();
                    second.logical_key = "logical-key-000".to_string();
                    store.insert(&second_key, serde_json::to_string(&second).unwrap());
                }
                _ => unreachable!(),
            }

            assert!(matches!(
                load_bws_keyring_config(&store).await,
                Err(SecretError::InvalidConfig(_))
            ));
        }
    }

    #[tokio::test]
    async fn bws_keyring_load_rejects_digest_mismatch() {
        let store = TransactionTestStore::default();
        store_bws_keyring_config(&store, &transaction_config(1, false))
            .await
            .unwrap();
        let generation = stored_generation(&store).await;
        let item_key = bws_binding_record_key(generation, 0);
        let mut item: StoredBwsKeyringBinding =
            serde_json::from_str(&store.entry(&item_key).unwrap()).unwrap();
        item.logical_key = "different-valid-key".to_string();
        store.insert(item_key, serde_json::to_string(&item).unwrap());

        assert!(matches!(
            load_bws_keyring_config(&store).await,
            Err(SecretError::InvalidConfig(_))
        ));
    }

    #[tokio::test]
    async fn bws_keyring_load_rejects_overcap_root_before_item_reads() {
        let store = TransactionTestStore::default();
        store_bws_keyring_config(&store, &transaction_config(1, false))
            .await
            .unwrap();
        let mut root: StoredBwsKeyringRoot =
            serde_json::from_str(&store.entry(PROVIDER_BWS_CONFIG_KEY).unwrap()).unwrap();
        root.binding_count = MAX_BWS_SECRET_BINDINGS + 1;
        store.insert(
            PROVIDER_BWS_CONFIG_KEY,
            serde_json::to_string(&root).unwrap(),
        );
        store.clear_operations();

        assert!(matches!(
            load_bws_keyring_config(&store).await,
            Err(SecretError::InvalidConfig(_))
        ));
        assert_eq!(
            store.operations(),
            vec![format!("get:{PROVIDER_BWS_CONFIG_KEY}")]
        );
    }

    #[tokio::test]
    async fn bws_keyring_commit_is_read_back_and_verified_before_old_cleanup() {
        let store = TransactionTestStore::default();
        store_bws_keyring_config(&store, &transaction_config(1, false))
            .await
            .unwrap();
        let old_generation = stored_generation(&store).await;
        store.clear_operations();

        store_bws_keyring_config_with_generation(
            &store,
            &transaction_config(2, false),
            Uuid::nil(),
        )
        .await
        .unwrap();

        let operations = store.operations();
        let root_set = operations
            .iter()
            .position(|operation| operation == &format!("set:{PROVIDER_BWS_CONFIG_KEY}"))
            .unwrap();
        let root_verify = operations
            .iter()
            .enumerate()
            .skip(root_set + 1)
            .find(|(_, operation)| *operation == &format!("get:{PROVIDER_BWS_CONFIG_KEY}"))
            .map(|(index, _)| index)
            .unwrap();
        let item_verify = operations
            .iter()
            .enumerate()
            .skip(root_verify + 1)
            .find(|(_, operation)| {
                *operation == &format!("get:{}", bws_binding_record_key(Uuid::nil(), 0))
            })
            .map(|(index, _)| index)
            .unwrap();
        let old_cleanup = operations
            .iter()
            .position(|operation| {
                operation == &format!("delete:{}", bws_binding_record_key(old_generation, 0))
            })
            .unwrap();
        assert!(root_set < root_verify && root_verify < item_verify && item_verify < old_cleanup);
    }

    #[tokio::test]
    async fn bws_keyring_clear_deletes_root_first_and_fails_closed() {
        let store = TransactionTestStore::default();
        store_bws_keyring_config(&store, &transaction_config(2, false))
            .await
            .unwrap();
        let generation = stored_generation(&store).await;
        store.clear_operations();
        store.fail_delete(PROVIDER_BWS_CONFIG_KEY);

        assert!(clear_bws_keyring_config(&store).await.is_err());
        assert!(store.entry(PROVIDER_BWS_CONFIG_KEY).is_some());
        assert!(!store.operations().iter().any(|operation| {
            operation.starts_with("delete:")
                && operation != &format!("delete:{PROVIDER_BWS_CONFIG_KEY}")
        }));

        store.state.lock().unwrap().fail_delete_key = None;
        store.clear_operations();
        clear_bws_keyring_config(&store).await.unwrap();
        let operations = store.operations();
        let root_delete = operations
            .iter()
            .position(|operation| operation == &format!("delete:{PROVIDER_BWS_CONFIG_KEY}"))
            .unwrap();
        let item_delete = operations
            .iter()
            .position(|operation| {
                operation == &format!("delete:{}", bws_binding_record_key(generation, 0))
            })
            .unwrap();
        assert!(root_delete < item_delete);
        assert!(store.entry(PROVIDER_BWS_CONFIG_KEY).is_none());
    }

    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "writes only fake metadata to a unique temporary Windows Credential Manager service"]
    async fn windows_os_keyring_round_trips_128_long_bindings_and_clears_authority() {
        let service = format!(
            "buzz-bws-transaction-integration-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        );
        let store = OsKeyringVault::new(service);
        let config = transaction_config(MAX_BWS_SECRET_BINDINGS, true);

        store_bws_keyring_config(&store, &config).await.unwrap();
        let loaded = load_bws_keyring_config(&store).await.unwrap().unwrap();
        assert!(configs_match(&loaded, &config));

        clear_bws_keyring_config(&store).await.unwrap();
        assert!(load_bws_keyring_config(&store).await.unwrap().is_none());
    }

    struct DelayedVault {
        delay: std::time::Duration,
    }

    struct BlockingVault {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl SecretVaultProvider for BlockingVault {
        fn name(&self) -> &str {
            "blocking"
        }

        async fn get_secret(&self, _key: &str) -> Result<String, SecretError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok("blocked-fixture-value".to_string())
        }

        async fn set_secret(
            &self,
            _key: &str,
            _value: &str,
            _description: Option<&str>,
        ) -> Result<(), SecretError> {
            Err(SecretError::NotFound("unsupported".to_string()))
        }

        async fn delete_secret(&self, _key: &str) -> Result<(), SecretError> {
            Err(SecretError::NotFound("unsupported".to_string()))
        }

        async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl SecretVaultProvider for DelayedVault {
        fn name(&self) -> &str {
            "delayed"
        }

        async fn get_secret(&self, _key: &str) -> Result<String, SecretError> {
            tokio::time::sleep(self.delay).await;
            Ok("delayed-fixture-value".to_string())
        }

        async fn set_secret(
            &self,
            _key: &str,
            _value: &str,
            _description: Option<&str>,
        ) -> Result<(), SecretError> {
            Err(SecretError::NotFound("unsupported".to_string()))
        }

        async fn delete_secret(&self, _key: &str) -> Result<(), SecretError> {
            Err(SecretError::NotFound("unsupported".to_string()))
        }

        async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn bws_root_serializes_directly_into_a_bounded_zeroizing_owner() {
        let root = StoredBwsKeyringRoot {
            schema_version: BWS_KEYRING_SCHEMA_VERSION,
            access_token: Zeroizing::new("machine-token-fixture".to_string()),
            project_id: Uuid::new_v4().to_string(),
            generation: Uuid::new_v4(),
            binding_count: 1,
            bindings_sha256: "00".repeat(32),
        };
        let mut writer = BoundedZeroizingJsonBuffer::new(BWS_KEYRING_ROOT_MAX_BYTES);
        serde_json::to_writer(&mut writer, &root).expect("bounded root serialization");
        let bytes = writer.into_inner();
        assert!(std::str::from_utf8(&bytes)
            .expect("root UTF-8")
            .contains("machine-token-fixture"));

        let mut undersized = BoundedZeroizingJsonBuffer::new(8);
        assert!(serde_json::to_writer(&mut undersized, &root).is_err());
        assert!(undersized.into_inner().len() <= 8);
    }

    #[test]
    fn backend_values_round_trip_and_unknown_values_fail_closed() {
        for backend in [
            SecretBackendKind::OsKeyring,
            SecretBackendKind::Bws,
            SecretBackendKind::LocalAirGapped,
        ] {
            assert_eq!(
                SecretBackendKind::parse(Some(backend.as_str())).unwrap(),
                backend
            );
        }
        assert!(SecretBackendKind::parse(Some("unknown")).is_err());
        assert_eq!(
            SecretBackendKind::parse(None).unwrap(),
            SecretBackendKind::OsKeyring
        );
    }

    #[tokio::test]
    async fn test_in_memory_vault_crud() {
        let vault = InMemorySecretVault::new();
        vault
            .set_secret("OPENROUTER_API_KEY", "sk-or-test-12345", Some("Test key"))
            .await
            .unwrap();

        let secret = vault.get_secret("OPENROUTER_API_KEY").await.unwrap();
        assert_eq!(secret, "sk-or-test-12345");

        let list = vault.list_secrets().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].key, "OPENROUTER_API_KEY");

        vault.delete_secret("OPENROUTER_API_KEY").await.unwrap();
        assert!(vault.get_secret("OPENROUTER_API_KEY").await.is_err());
    }

    #[tokio::test]
    async fn test_secret_broker_abac_leasing() {
        let vault = Arc::new(InMemorySecretVault::new());
        vault
            .set_secret("OPENROUTER_API_KEY", "test-value-1", None)
            .await
            .unwrap();
        vault
            .set_secret("DATABASE_PASSWORD", "super-secret-db", None)
            .await
            .unwrap();

        let broker = SecretBroker::new(vec![vault]);

        // Define policy for agent1: only permitted to access OPENROUTER_API_KEY on tool "model_inference"
        broker
            .add_policy(SecretPolicy {
                policy_id: "policy-1".to_string(),
                agent_pubkey: "agent1".to_string(),
                allowed_secrets: vec!["OPENROUTER_API_KEY".to_string()],
                allowed_tools: vec!["model_inference".to_string()],
                max_lease_ttl_secs: 60,
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            })
            .await
            .unwrap();

        // Authorized lease
        let lease = broker
            .acquire_lease(
                "policy-1",
                "agent1",
                "model_inference",
                "OPENROUTER_API_KEY",
            )
            .await
            .unwrap();
        assert_eq!(lease.value, "test-value-1");
        assert!(lease.is_valid());
        assert!(!format!("{lease:?}").contains("test-value-1"));
        let active = broker.active_leases().await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].lease_id, lease.lease_id);
        assert_eq!(active[0].secret_key, "OPENROUTER_API_KEY");
        let serialized = serde_json::to_string(&active[0]).unwrap();
        assert!(!serialized.contains("test-value-1"));
        assert!(!serialized.contains("value"));

        // Unauthorized tool
        let tool_denied = broker
            .acquire_lease("policy-1", "agent1", "terminal", "OPENROUTER_API_KEY")
            .await;
        assert!(tool_denied.is_err());

        // Unauthorized secret
        let secret_denied = broker
            .acquire_lease("policy-1", "agent1", "model_inference", "DATABASE_PASSWORD")
            .await;
        assert!(secret_denied.is_err());

        // Unauthorized agent
        let agent_denied = broker
            .acquire_lease(
                "policy-1",
                "agent_unknown",
                "model_inference",
                "OPENROUTER_API_KEY",
            )
            .await;
        assert!(agent_denied.is_err());
    }

    #[test]
    fn policies_reject_whitespace_only_identity_and_acl_entries() {
        let broker = SecretBroker::new(Vec::new());
        let valid = SecretPolicy {
            policy_id: "policy-a".to_string(),
            agent_pubkey: "agent-a".to_string(),
            allowed_secrets: vec!["secret-a".to_string()],
            allowed_tools: vec!["tool-a".to_string()],
            max_lease_ttl_secs: 60,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        for invalid in [
            SecretPolicy {
                policy_id: " \t".to_string(),
                ..valid.clone()
            },
            SecretPolicy {
                agent_pubkey: "\n".to_string(),
                ..valid.clone()
            },
            SecretPolicy {
                allowed_secrets: vec!["secret-a".to_string(), "  ".to_string()],
                ..valid.clone()
            },
            SecretPolicy {
                allowed_tools: vec!["\r\n".to_string()],
                ..valid.clone()
            },
        ] {
            assert!(matches!(
                broker.set_policy(invalid),
                Err(SecretError::InvalidConfig(_))
            ));
        }
    }

    #[test]
    fn policies_enforce_every_identity_acl_ttl_and_lifetime_bound() {
        let broker = SecretBroker::new(Vec::new());
        let valid = SecretPolicy {
            policy_id: "policy-a".to_string(),
            agent_pubkey: "agent-a".to_string(),
            allowed_secrets: vec!["secret-a".to_string()],
            allowed_tools: vec!["tool-a".to_string()],
            max_lease_ttl_secs: 60,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        let too_many = (0..=MAX_POLICY_ACL_ENTRIES)
            .map(|index| format!("entry-{index}"))
            .collect::<Vec<_>>();
        let oversized = "x".repeat(MAX_POLICY_IDENTIFIER_BYTES + 1);
        let invalid = [
            SecretPolicy {
                policy_id: "policy\u{0}id".to_string(),
                ..valid.clone()
            },
            SecretPolicy {
                agent_pubkey: "agent\u{7f}id".to_string(),
                ..valid.clone()
            },
            SecretPolicy {
                policy_id: oversized.clone(),
                ..valid.clone()
            },
            SecretPolicy {
                agent_pubkey: oversized.clone(),
                ..valid.clone()
            },
            SecretPolicy {
                allowed_secrets: Vec::new(),
                ..valid.clone()
            },
            SecretPolicy {
                allowed_tools: Vec::new(),
                ..valid.clone()
            },
            SecretPolicy {
                allowed_secrets: too_many.clone(),
                ..valid.clone()
            },
            SecretPolicy {
                allowed_tools: too_many,
                ..valid.clone()
            },
            SecretPolicy {
                allowed_secrets: vec![oversized.clone()],
                ..valid.clone()
            },
            SecretPolicy {
                allowed_tools: vec![oversized],
                ..valid.clone()
            },
            SecretPolicy {
                allowed_secrets: vec!["secret\nname".to_string()],
                ..valid.clone()
            },
            SecretPolicy {
                allowed_tools: vec!["tool\u{7f}name".to_string()],
                ..valid.clone()
            },
            SecretPolicy {
                max_lease_ttl_secs: 0,
                ..valid.clone()
            },
            SecretPolicy {
                max_lease_ttl_secs: MAX_SECRET_LEASE_TTL_SECS + 1,
                ..valid.clone()
            },
            SecretPolicy {
                expires_at: Utc::now(),
                ..valid.clone()
            },
            SecretPolicy {
                expires_at: Utc::now()
                    + chrono::Duration::seconds(MAX_POLICY_LIFETIME_SECS as i64 + 1),
                ..valid.clone()
            },
        ];
        for policy in invalid {
            assert!(matches!(
                broker.set_policy(policy),
                Err(SecretError::InvalidConfig(_))
            ));
        }
        assert!(broker.set_policy(valid).is_ok());

        let at_bounds = SecretPolicy {
            policy_id: "p".repeat(MAX_POLICY_IDENTIFIER_BYTES),
            agent_pubkey: "a".repeat(MAX_POLICY_IDENTIFIER_BYTES),
            allowed_secrets: (0..MAX_POLICY_ACL_ENTRIES)
                .map(|index| format!("secret-{index}"))
                .collect(),
            allowed_tools: (0..MAX_POLICY_ACL_ENTRIES)
                .map(|index| format!("tool-{index}"))
                .collect(),
            max_lease_ttl_secs: MAX_SECRET_LEASE_TTL_SECS,
            expires_at: Utc::now() + chrono::Duration::seconds(MAX_POLICY_LIFETIME_SECS as i64 - 1),
        };
        assert!(broker.set_policy(at_bounds).is_ok());
    }

    #[tokio::test]
    async fn policy_narrowing_while_provider_is_blocked_denies_lease() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let broker = Arc::new(SecretBroker::new(vec![Arc::new(BlockingVault {
            entered: entered.clone(),
            release: release.clone(),
        })]));
        let policy = SecretPolicy {
            policy_id: "blocking-policy".to_string(),
            agent_pubkey: "blocking-agent".to_string(),
            allowed_secrets: vec!["blocking-secret".to_string()],
            allowed_tools: vec!["blocking-tool".to_string()],
            max_lease_ttl_secs: 60,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        broker.set_policy(policy.clone()).unwrap();

        let acquiring = {
            let broker = broker.clone();
            tokio::spawn(async move {
                broker
                    .acquire_lease(
                        "blocking-policy",
                        "blocking-agent",
                        "blocking-tool",
                        "blocking-secret",
                    )
                    .await
            })
        };
        entered.notified().await;
        broker
            .set_policy(SecretPolicy {
                allowed_secrets: vec!["different-secret".to_string()],
                max_lease_ttl_secs: 1,
                expires_at: Utc::now() + chrono::Duration::seconds(1),
                ..policy
            })
            .unwrap();
        release.notify_one();

        assert!(matches!(
            acquiring.await.unwrap(),
            Err(SecretError::AccessDenied { .. })
        ));
        assert!(broker.active_leases().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn policy_removal_while_provider_is_blocked_denies_lease() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let broker = Arc::new(SecretBroker::new(vec![Arc::new(BlockingVault {
            entered: entered.clone(),
            release: release.clone(),
        })]));
        broker
            .set_policy(SecretPolicy {
                policy_id: "removed-policy".to_string(),
                agent_pubkey: "blocking-agent".to_string(),
                allowed_secrets: vec!["blocking-secret".to_string()],
                allowed_tools: vec!["blocking-tool".to_string()],
                max_lease_ttl_secs: 60,
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            })
            .unwrap();

        let acquiring = {
            let broker = broker.clone();
            tokio::spawn(async move {
                broker
                    .acquire_lease(
                        "removed-policy",
                        "blocking-agent",
                        "blocking-tool",
                        "blocking-secret",
                    )
                    .await
            })
        };
        entered.notified().await;
        broker.remove_policy("removed-policy").unwrap();
        release.notify_one();

        assert!(matches!(
            acquiring.await.unwrap(),
            Err(SecretError::AccessDenied { .. })
        ));
        assert!(broker.active_leases().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn current_policy_ttl_governs_after_provider_returns() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let broker = Arc::new(SecretBroker::new(vec![Arc::new(BlockingVault {
            entered: entered.clone(),
            release: release.clone(),
        })]));
        let mut policy = SecretPolicy {
            policy_id: "ttl-policy".to_string(),
            agent_pubkey: "blocking-agent".to_string(),
            allowed_secrets: vec!["blocking-secret".to_string()],
            allowed_tools: vec!["blocking-tool".to_string()],
            max_lease_ttl_secs: 60,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        broker.set_policy(policy.clone()).unwrap();

        let acquiring = {
            let broker = broker.clone();
            tokio::spawn(async move {
                broker
                    .acquire_lease(
                        "ttl-policy",
                        "blocking-agent",
                        "blocking-tool",
                        "blocking-secret",
                    )
                    .await
            })
        };
        entered.notified().await;
        policy.max_lease_ttl_secs = 1;
        policy.expires_at = Utc::now() + chrono::Duration::seconds(2);
        broker.set_policy(policy).unwrap();
        release.notify_one();

        let lease = acquiring.await.unwrap().unwrap();
        let active = broker.active_leases().await.unwrap();
        let metadata = active
            .iter()
            .find(|metadata| metadata.lease_id == lease.lease_id)
            .unwrap();
        assert!(lease.expires_at <= metadata.issued_at + chrono::Duration::seconds(1));
    }

    #[tokio::test]
    async fn broker_rejects_1025th_live_policy_without_evicting_authority() {
        let vault = Arc::new(InMemorySecretVault::new());
        vault
            .set_secret("bounded-secret", "bounded-fixture-value", None)
            .await
            .unwrap();
        let broker = SecretBroker::new(vec![vault]);
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let policy = |index: usize, agent_pubkey: &str| SecretPolicy {
            policy_id: format!("bounded-policy-{index:04}"),
            agent_pubkey: agent_pubkey.to_string(),
            allowed_secrets: vec!["bounded-secret".to_string()],
            allowed_tools: vec!["bounded-tool".to_string()],
            max_lease_ttl_secs: 60,
            expires_at,
        };
        for index in 0..MAX_SECRET_POLICY_ROWS {
            broker.set_policy(policy(index, "bounded-agent")).unwrap();
        }

        broker
            .set_policy(policy(0, "updated-bounded-agent"))
            .expect("an existing policy update remains permitted at capacity");
        assert!(matches!(
            broker.set_policy(policy(MAX_SECRET_POLICY_ROWS, "rejected-agent")),
            Err(SecretError::InvalidConfig(_))
        ));

        let projected = broker.policies().await.unwrap();
        assert_eq!(projected.len(), MAX_SECRET_POLICY_ROWS);
        assert!(projected
            .iter()
            .any(|policy| policy.policy_id == "bounded-policy-0000"
                && policy.agent_pubkey == "updated-bounded-agent"));
        assert!(projected
            .iter()
            .all(|policy| policy.policy_id != "bounded-policy-1024"));
        assert!(matches!(
            broker
                .acquire_lease(
                    "bounded-policy-1024",
                    "rejected-agent",
                    "bounded-tool",
                    "bounded-secret",
                )
                .await,
            Err(SecretError::AccessDenied { .. })
        ));
    }

    #[tokio::test]
    async fn audited_broker_rejects_1025th_policy_without_diverging_or_evicting() {
        let path = std::env::temp_dir().join(format!(
            "buzz-secret-policy-audit-cap-{}.db",
            Uuid::new_v4()
        ));
        let audit = Arc::new(SecretAuditStore::open(&path).unwrap());
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let mut connection = audit.connect().unwrap();
        let transaction = connection.transaction().unwrap();
        for index in 0..MAX_SECRET_POLICY_ROWS {
            transaction
                .execute(
                    "INSERT INTO secret_policies_v2
                        (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                         max_lease_ttl_secs, expires_at_unix_ms)
                     VALUES (?1, 'audited-agent', '[\"audited-secret\"]',
                             '[\"audited-tool\"]', 60, ?2)",
                    params![
                        format!("audited-policy-{index:04}"),
                        expires_at.timestamp_millis()
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        drop(connection);

        audit
            .set_policy(&SecretPolicy {
                policy_id: "audited-policy-0000".to_string(),
                agent_pubkey: "updated-audited-agent".to_string(),
                allowed_secrets: vec!["audited-secret".to_string()],
                allowed_tools: vec!["audited-tool".to_string()],
                max_lease_ttl_secs: 60,
                expires_at,
            })
            .expect("an audited update remains permitted at capacity");
        let vault = Arc::new(InMemorySecretVault::new());
        vault
            .set_secret("audited-secret", "audited-fixture-value", None)
            .await
            .unwrap();
        let broker = SecretBroker::with_audit(vec![vault], audit.clone());
        let rejected = SecretPolicy {
            policy_id: "audited-policy-1024".to_string(),
            agent_pubkey: "rejected-audited-agent".to_string(),
            allowed_secrets: vec!["audited-secret".to_string()],
            allowed_tools: vec!["audited-tool".to_string()],
            max_lease_ttl_secs: 60,
            expires_at,
        };

        assert!(matches!(
            broker.set_policy(rejected),
            Err(SecretError::InvalidConfig(_))
        ));
        let projected = broker.policies().await.unwrap();
        assert_eq!(projected.len(), MAX_SECRET_POLICY_ROWS);
        assert!((0..MAX_SECRET_POLICY_ROWS).all(|index| projected
            .iter()
            .any(|policy| policy.policy_id == format!("audited-policy-{index:04}"))));
        assert!(projected
            .iter()
            .any(|policy| policy.policy_id == "audited-policy-0000"
                && policy.agent_pubkey == "updated-audited-agent"));
        assert!(projected
            .iter()
            .all(|policy| policy.policy_id != "audited-policy-1024"));
        assert!(matches!(
            broker
                .acquire_lease(
                    "audited-policy-1024",
                    "rejected-audited-agent",
                    "audited-tool",
                    "audited-secret",
                )
                .await,
            Err(SecretError::AccessDenied { .. })
        ));

        drop(broker);
        drop(audit);
        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[tokio::test]
    async fn policies_are_capability_scoped_removed_independently_and_exactly_bounded() {
        let vault = Arc::new(InMemorySecretVault::new());
        vault.set_secret("secret-a", "value-a", None).await.unwrap();
        vault.set_secret("secret-b", "value-b", None).await.unwrap();
        let broker = SecretBroker::new(vec![vault]);
        let policy_expiry = Utc::now() + chrono::Duration::minutes(5);
        for (policy_id, secret) in [("cap-a", "secret-a"), ("cap-b", "secret-b")] {
            broker
                .add_policy(SecretPolicy {
                    policy_id: policy_id.to_string(),
                    agent_pubkey: "shared-agent".to_string(),
                    allowed_secrets: vec![secret.to_string()],
                    allowed_tools: vec!["tool".to_string()],
                    max_lease_ttl_secs: 300,
                    expires_at: policy_expiry,
                })
                .await
                .unwrap();
        }

        let exact_deadline = (Utc::now() + chrono::Duration::milliseconds(750)).timestamp_millis();
        let lease = broker
            .acquire_lease_until_ms("cap-a", "shared-agent", "tool", "secret-a", exact_deadline)
            .await
            .unwrap();
        assert!(lease.expires_at.timestamp_millis() <= exact_deadline);
        assert!(broker
            .acquire_lease("cap-b", "shared-agent", "tool", "secret-b")
            .await
            .is_ok());

        broker.remove_policy("cap-a").unwrap();
        assert!(broker
            .acquire_lease("cap-a", "shared-agent", "tool", "secret-a")
            .await
            .is_err());
        assert!(broker
            .acquire_lease("cap-b", "shared-agent", "tool", "secret-b")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn slow_provider_cannot_return_a_lease_after_exact_deadline() {
        let broker = SecretBroker::new(vec![Arc::new(DelayedVault {
            delay: std::time::Duration::from_millis(40),
        })]);
        broker
            .add_policy(SecretPolicy {
                policy_id: "slow-capability".to_string(),
                agent_pubkey: "slow-agent".to_string(),
                allowed_secrets: vec!["slow-secret".to_string()],
                allowed_tools: vec!["slow-tool".to_string()],
                max_lease_ttl_secs: 60,
                expires_at: Utc::now() + chrono::Duration::minutes(1),
            })
            .await
            .unwrap();
        let exact_deadline = (Utc::now() + chrono::Duration::milliseconds(20)).timestamp_millis();

        let result = broker
            .acquire_lease_until_ms(
                "slow-capability",
                "slow-agent",
                "slow-tool",
                "slow-secret",
                exact_deadline,
            )
            .await;

        assert!(matches!(result, Err(SecretError::AccessDenied { .. })));
        assert!(broker.active_leases().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn in_memory_active_lease_projection_is_bounded() {
        let vault = Arc::new(InMemorySecretVault::new());
        vault
            .set_secret("bounded-secret", "fixture-value", None)
            .await
            .unwrap();
        let broker = SecretBroker::new(vec![vault]);
        broker
            .add_policy(SecretPolicy {
                policy_id: "bounded-policy".to_string(),
                agent_pubkey: "bounded-agent".to_string(),
                allowed_secrets: vec!["bounded-secret".to_string()],
                allowed_tools: vec!["bounded-tool".to_string()],
                max_lease_ttl_secs: 60,
                expires_at: Utc::now() + chrono::Duration::minutes(2),
            })
            .await
            .unwrap();

        for _ in 0..=MAX_ACTIVE_SECRET_LEASE_ROWS {
            broker
                .acquire_lease(
                    "bounded-policy",
                    "bounded-agent",
                    "bounded-tool",
                    "bounded-secret",
                )
                .await
                .unwrap();
        }

        assert_eq!(
            broker.active_leases().await.unwrap().len(),
            MAX_ACTIVE_SECRET_LEASE_ROWS
        );
    }

    #[tokio::test]
    async fn sqlite_audit_projection_is_shared_and_never_contains_values() {
        let path = std::env::temp_dir().join(format!("buzz-secret-audit-{}.db", Uuid::new_v4()));
        let audit_writer = Arc::new(SecretAuditStore::open(&path).unwrap());
        let settings = audit_writer.connect().unwrap();
        let journal_mode: String = settings
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let busy_timeout: i64 = settings
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(busy_timeout, 5_000);
        drop(settings);
        let vault = Arc::new(InMemorySecretVault::new());
        vault
            .set_secret("secret-id", "audit-fixture-value", None)
            .await
            .unwrap();
        let writer = SecretBroker::with_audit(vec![vault], audit_writer);
        writer
            .add_policy(SecretPolicy {
                policy_id: "policy-a".to_string(),
                agent_pubkey: "agent-a".to_string(),
                allowed_secrets: vec!["secret-id".to_string()],
                allowed_tools: vec!["tool-a".to_string()],
                max_lease_ttl_secs: 60,
                expires_at: Utc::now() + chrono::Duration::minutes(5),
            })
            .await
            .unwrap();
        writer
            .acquire_lease("policy-a", "agent-a", "tool-a", "secret-id")
            .await
            .unwrap();

        let reader =
            SecretBroker::with_audit(Vec::new(), Arc::new(SecretAuditStore::open(&path).unwrap()));
        assert_eq!(reader.policies().await.unwrap().len(), 1);
        let active = reader.active_leases().await.unwrap();
        assert_eq!(active.len(), 1);
        assert!(!serde_json::to_string(&active)
            .unwrap()
            .contains("audit-fixture-value"));
        drop(reader);
        drop(writer);

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[test]
    fn sqlite_policy_load_omits_and_prunes_malformed_durable_rows() {
        let path =
            std::env::temp_dir().join(format!("buzz-secret-policy-load-{}.db", Uuid::new_v4()));
        let store = SecretAuditStore::open(&path).unwrap();
        let valid = SecretPolicy {
            policy_id: "valid-policy".to_string(),
            agent_pubkey: "valid-agent".to_string(),
            allowed_secrets: vec!["secret".to_string()],
            allowed_tools: vec!["tool".to_string()],
            max_lease_ttl_secs: 60,
            expires_at: Utc::now() + chrono::Duration::minutes(5),
        };
        store.set_policy(&valid).unwrap();
        let invalid_for_persistence = SecretPolicy {
            max_lease_ttl_secs: MAX_SECRET_LEASE_TTL_SECS + 1,
            ..valid.clone()
        };
        assert!(matches!(
            store.set_policy(&invalid_for_persistence),
            Err(SecretError::InvalidConfig(_))
        ));
        let connection = store.connect().unwrap();
        connection
            .execute(
                "INSERT INTO secret_policies_v2
                    (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                     max_lease_ttl_secs, expires_at_unix_ms)
                 VALUES ('malformed-policy', 'agent', '[not-json', '[\"tool\"]', 60, ?1)",
                [valid.expires_at.timestamp_millis()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO secret_policies_v2
                    (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                     max_lease_ttl_secs, expires_at_unix_ms)
                 VALUES ('invalid-policy', 'agent', '[\"secret\"]', '[\"tool\"]', ?1, ?2)",
                params![
                    MAX_SECRET_LEASE_TTL_SECS as i64 + 1,
                    valid.expires_at.timestamp_millis()
                ],
            )
            .unwrap();
        drop(connection);

        let policies = store.policies().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].policy_id, "valid-policy");
        let remaining: i64 = store
            .connect()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM secret_policies_v2", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 1, "invalid durable rows should be pruned");

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[test]
    fn policy_writes_prune_expired_rows_and_reject_new_policy_over_cap() {
        let path =
            std::env::temp_dir().join(format!("buzz-secret-policy-cap-{}.db", Uuid::new_v4()));
        let store = SecretAuditStore::open(&path).unwrap();
        let now = Utc::now();
        let mut connection = store.connect().unwrap();
        let transaction = connection.transaction().unwrap();
        transaction
            .execute(
                "INSERT INTO secret_policies_v2
                    (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                     max_lease_ttl_secs, expires_at_unix_ms)
                 VALUES ('expired-policy', 'agent', '[\"secret\"]', '[\"tool\"]', 60, ?1)",
                [(now - chrono::Duration::minutes(1)).timestamp_millis()],
            )
            .unwrap();
        for index in 0..(MAX_SECRET_POLICY_ROWS + 8) {
            transaction
                .execute(
                    "INSERT INTO secret_policies_v2
                        (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                         max_lease_ttl_secs, expires_at_unix_ms)
                     VALUES (?1, 'agent', '[\"secret\"]', '[\"tool\"]', 60, ?2)",
                    params![
                        format!("seed-policy-{index:04}"),
                        (now + chrono::Duration::hours(1)
                            + chrono::Duration::milliseconds(index as i64))
                        .timestamp_millis()
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        drop(connection);

        let rejected = store.set_policy(&SecretPolicy {
            policy_id: "newest-policy".to_string(),
            agent_pubkey: "agent".to_string(),
            allowed_secrets: vec!["secret".to_string()],
            allowed_tools: vec!["tool".to_string()],
            max_lease_ttl_secs: 60,
            expires_at: now + chrono::Duration::hours(2),
        });
        assert!(matches!(rejected, Err(SecretError::InvalidConfig(_))));

        let connection = store.connect().unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM secret_policies_v2", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, (MAX_SECRET_POLICY_ROWS + 8) as i64);
        for (policy_id, expected) in [
            ("expired-policy", 0_i64),
            ("seed-policy-0000", 1_i64),
            ("newest-policy", 0_i64),
        ] {
            let present: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM secret_policies_v2 WHERE policy_id = ?1",
                    [policy_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(present, expected, "unexpected retention for {policy_id}");
        }
        drop(connection);

        let projected = store.policies().unwrap();
        assert_eq!(projected.len(), MAX_SECRET_POLICY_ROWS);
        let connection = store.connect().unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM secret_policies_v2", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, MAX_SECRET_POLICY_ROWS as i64);
        let oldest_present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM secret_policies_v2 WHERE policy_id = 'seed-policy-0000'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(oldest_present, 0);
        drop(connection);

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[test]
    fn restarted_policy_projection_is_read_bounded_and_prunes_malformed_rows() {
        let path = std::env::temp_dir().join(format!(
            "buzz-secret-policy-restart-cap-{}.db",
            Uuid::new_v4()
        ));
        let store = SecretAuditStore::open(&path).unwrap();
        let now = Utc::now();
        let mut connection = store.connect().unwrap();
        let transaction = connection.transaction().unwrap();
        for index in 0..(MAX_SECRET_POLICY_ROWS + 20) {
            transaction
                .execute(
                    "INSERT INTO secret_policies_v2
                        (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                         max_lease_ttl_secs, expires_at_unix_ms)
                     VALUES (?1, 'agent', '[\"secret\"]', '[\"tool\"]', 60, ?2)",
                    params![
                        format!("restart-policy-{index:04}"),
                        (now + chrono::Duration::hours(1)
                            + chrono::Duration::milliseconds(index as i64))
                        .timestamp_millis()
                    ],
                )
                .unwrap();
        }
        transaction
            .execute(
                "INSERT INTO secret_policies_v2
                    (policy_id, agent_pubkey, allowed_secrets_json, allowed_tools_json,
                     max_lease_ttl_secs, expires_at_unix_ms)
                 VALUES ('malformed-newest', 'agent', '[not-json', '[\"tool\"]', 60, ?1)",
                [(now + chrono::Duration::hours(2)).timestamp_millis()],
            )
            .unwrap();
        transaction.commit().unwrap();
        drop(connection);
        drop(store);

        let restarted = SecretAuditStore::open(&path).unwrap();
        let policies = restarted.policies().unwrap();
        assert!(policies.len() <= MAX_SECRET_POLICY_ROWS);
        assert!(policies
            .iter()
            .all(|policy| policy.policy_id != "malformed-newest"));
        let connection = restarted.connect().unwrap();
        let durable_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM secret_policies_v2", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(durable_count <= MAX_SECRET_POLICY_ROWS as i64);
        let malformed_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM secret_policies_v2 WHERE policy_id = 'malformed-newest'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(malformed_count, 0, "malformed durable row was not pruned");
        drop(connection);

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[test]
    fn restarted_active_lease_projection_omits_and_prunes_malformed_rows() {
        let path = std::env::temp_dir().join(format!(
            "buzz-secret-lease-restart-corrupt-{}.db",
            Uuid::new_v4()
        ));
        let store = SecretAuditStore::open(&path).unwrap();
        let now = Utc::now();
        let valid_lease_id = format!("lease_{}", Uuid::new_v4());
        let semantic_invalid_lease_id = format!("lease_{}", Uuid::new_v4());
        let connection = store.connect().unwrap();
        connection
            .execute(
                "INSERT INTO active_secret_leases
                    (lease_id, secret_key, agent_pubkey, tool,
                     issued_at_unix_ms, expires_at_unix_ms)
                 VALUES (?1, 'secret', 'agent', 'tool', ?2, ?3)",
                params![
                    &valid_lease_id,
                    now.timestamp_millis(),
                    (now + chrono::Duration::hours(1)).timestamp_millis()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO active_secret_leases
                    (lease_id, secret_key, agent_pubkey, tool,
                     issued_at_unix_ms, expires_at_unix_ms)
                 VALUES (?1, '', 'agent', 'tool', ?2, ?3)",
                params![
                    semantic_invalid_lease_id,
                    now.timestamp_millis(),
                    (now + chrono::Duration::hours(1)).timestamp_millis()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO active_secret_leases
                    (lease_id, secret_key, agent_pubkey, tool,
                     issued_at_unix_ms, expires_at_unix_ms)
                 VALUES ('malformed-restart-lease', X'00', 'agent', 'tool', ?1, ?2)",
                params![
                    now.timestamp_millis(),
                    (now + chrono::Duration::hours(1)).timestamp_millis()
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO active_secret_leases
                    (lease_id, secret_key, agent_pubkey, tool,
                     issued_at_unix_ms, expires_at_unix_ms)
                 VALUES ('expired-restart-lease', 'secret', 'agent', 'tool', ?1, ?2)",
                params![
                    (now - chrono::Duration::minutes(2)).timestamp_millis(),
                    (now - chrono::Duration::minutes(1)).timestamp_millis()
                ],
            )
            .unwrap();
        drop(connection);
        drop(store);

        let restarted = SecretAuditStore::open(&path).unwrap();
        let leases = restarted.active_leases().unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].lease_id, valid_lease_id);
        let remaining: i64 = restarted
            .connect()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM active_secret_leases", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(remaining, 1, "expired and malformed rows should be pruned");

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[test]
    fn restarted_active_lease_projection_is_deterministically_bounded() {
        let path = std::env::temp_dir().join(format!(
            "buzz-secret-lease-restart-cap-{}.db",
            Uuid::new_v4()
        ));
        let store = SecretAuditStore::open(&path).unwrap();
        let now = Utc::now();
        let lease_id = |index: usize| format!("lease_{}", Uuid::from_u128(index as u128 + 1));
        let mut connection = store.connect().unwrap();
        let transaction = connection.transaction().unwrap();
        for index in 0..=MAX_ACTIVE_SECRET_LEASE_ROWS {
            transaction
                .execute(
                    "INSERT INTO active_secret_leases
                        (lease_id, secret_key, agent_pubkey, tool,
                         issued_at_unix_ms, expires_at_unix_ms)
                     VALUES (?1, 'secret', 'agent', 'tool', ?2, ?3)",
                    params![
                        lease_id(index),
                        (now + chrono::Duration::milliseconds(index as i64)).timestamp_millis(),
                        (now + chrono::Duration::hours(1)).timestamp_millis()
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        drop(connection);
        drop(store);

        let restarted = SecretAuditStore::open(&path).unwrap();
        let leases = restarted.active_leases().unwrap();
        assert_eq!(leases.len(), MAX_ACTIVE_SECRET_LEASE_ROWS);
        assert!(leases.iter().all(|lease| lease.lease_id != lease_id(0)));
        assert!(leases.iter().any(|lease| lease.lease_id == lease_id(1024)));
        let durable_count: i64 = restarted
            .connect()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM active_secret_leases", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(durable_count, MAX_ACTIVE_SECRET_LEASE_ROWS as i64);

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[test]
    fn lease_metadata_is_semantically_validated_before_persistence() {
        let path = std::env::temp_dir().join(format!(
            "buzz-secret-lease-validation-{}.db",
            Uuid::new_v4()
        ));
        let store = SecretAuditStore::open(&path).unwrap();
        let now = Utc::now();
        let valid = SecretLeaseMetadata {
            lease_id: format!("lease_{}", Uuid::new_v4()),
            secret_key: "secret".to_string(),
            agent_pubkey: "agent".to_string(),
            tool: "tool".to_string(),
            issued_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        };
        for invalid in [
            SecretLeaseMetadata {
                lease_id: "not-a-lease-uuid".to_string(),
                ..valid.clone()
            },
            SecretLeaseMetadata {
                secret_key: "  ".to_string(),
                ..valid.clone()
            },
            SecretLeaseMetadata {
                tool: "tool\nname".to_string(),
                ..valid.clone()
            },
            SecretLeaseMetadata {
                agent_pubkey: "a".repeat(MAX_POLICY_IDENTIFIER_BYTES + 1),
                ..valid.clone()
            },
            SecretLeaseMetadata {
                issued_at: now + chrono::Duration::minutes(10),
                expires_at: now + chrono::Duration::minutes(5),
                ..valid.clone()
            },
            SecretLeaseMetadata {
                expires_at: now + chrono::Duration::seconds(MAX_SECRET_LEASE_TTL_SECS as i64 + 1),
                ..valid.clone()
            },
        ] {
            assert!(matches!(
                store.record_lease(&invalid),
                Err(SecretError::InvalidConfig(_))
            ));
        }
        let count: i64 = store
            .connect()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM active_secret_leases", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[test]
    fn lease_writes_prune_expired_rows_and_enforce_deterministic_cap() {
        const EXPECTED_CAP: usize = 1_024;
        let path = std::env::temp_dir().join(format!("buzz-secret-cap-{}.db", Uuid::new_v4()));
        let store = SecretAuditStore::open(&path).unwrap();
        let mut connection = store.connect().unwrap();
        let transaction = connection.transaction().unwrap();
        let now = Utc::now();
        let seed_lease_id = |index: usize| format!("lease_{}", Uuid::from_u128(index as u128 + 1));
        transaction
            .execute(
                "INSERT INTO active_secret_leases
                    (lease_id, secret_key, agent_pubkey, tool, issued_at_unix_ms, expires_at_unix_ms)
                 VALUES ('expired-row', 'secret', 'agent', 'tool', ?1, ?2)",
                params![
                    (now - chrono::Duration::minutes(2)).timestamp_millis(),
                    (now - chrono::Duration::minutes(1)).timestamp_millis()
                ],
            )
            .unwrap();
        for index in 0..(EXPECTED_CAP + 12) {
            transaction
                .execute(
                    "INSERT INTO active_secret_leases
                        (lease_id, secret_key, agent_pubkey, tool, issued_at_unix_ms, expires_at_unix_ms)
                     VALUES (?1, 'secret', 'agent', 'tool', ?2, ?3)",
                    params![
                        seed_lease_id(index),
                        (now + chrono::Duration::milliseconds(index as i64)).timestamp_millis(),
                        (now + chrono::Duration::hours(1)).timestamp_millis()
                    ],
                )
                .unwrap();
        }
        transaction.commit().unwrap();
        drop(connection);

        let newest = SecretLeaseMetadata {
            lease_id: format!("lease_{}", Uuid::new_v4()),
            secret_key: "secret".to_string(),
            agent_pubkey: "agent".to_string(),
            tool: "tool".to_string(),
            issued_at: now + chrono::Duration::seconds(2),
            expires_at: now + chrono::Duration::hours(1),
        };
        store.record_lease(&newest).unwrap();

        let connection = store.connect().unwrap();
        let count: i64 = connection
            .query_row("SELECT COUNT(*) FROM active_secret_leases", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, EXPECTED_CAP as i64);
        let expired_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM active_secret_leases WHERE lease_id = 'expired-row'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expired_count, 0);
        let newest_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM active_secret_leases WHERE lease_id = ?1",
                [&newest.lease_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(newest_count, 1);
        drop(connection);

        for candidate in [
            path.clone(),
            PathBuf::from(format!("{}-wal", path.display())),
            PathBuf::from(format!("{}-shm", path.display())),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }
}
