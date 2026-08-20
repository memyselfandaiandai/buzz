//! Buzz-owned provider-neutral durable workspace controller core.
//!
//! SQLite is the authority for admission, scoped reservations, lifecycle,
//! cancellation, terminal receipts, artifact accounting, and cleanup claims.
//! Provider state is deliberately outside this ledger and is reconciled by an
//! adapter using session/workspace identity.

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

pub mod observer;
pub use observer::*;

const BUSY_TIMEOUT: Duration = Duration::from_secs(15);
/// Maximum lifetime of a locally modeled activation capability.
pub const MAX_ACTIVATION_TTL_SECONDS: i64 = 300;
type TerminalSessionRow = (
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
);
type LaunchValidationRow = (String, i64, String, String, i64, String, i64, String, i64);
type ExistingLaunchAuthorizationRow = (
    String,
    String,
    String,
    i64,
    String,
    String,
    String,
    i64,
    String,
);

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("session not found")]
    SessionNotFound,
    #[error("JTI has already been consumed by another session")]
    JtiReplay,
    #[error("capability digest has already been consumed by another session")]
    CapabilityReplay,
    #[error("workspace is already owned by another session")]
    WorkspaceOwned,
    #[error("session already exists with different immutable bindings")]
    SessionConflict,
    #[error("scope capacity exceeded: active={active}, limit={limit}")]
    CapacityExceeded { active: u32, limit: u32 },
    #[error("invalid transition from {from} to {to}")]
    InvalidTransition { from: Lifecycle, to: Lifecycle },
    #[error("ownership does not match the admitted session")]
    OwnershipMismatch,
    #[error("cleanup claim does not match")]
    CleanupClaimMismatch,
    #[error("artifact byte limit exceeded")]
    ArtifactLimitExceeded,
    #[error("artifact path already exists")]
    DuplicateArtifact,
    #[error("invalid artifact")]
    InvalidArtifact,
    #[error("terminal receipt does not match durable artifact accounting")]
    TerminalReceiptMismatch,
    #[error("terminal receipt digest has already been used")]
    ReceiptReplay,
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    #[error("corrupt lifecycle value in ledger: {0}")]
    CorruptState(String),
    #[error("simulated controller crash at {0:?}")]
    SimulatedCrash(CrashPoint),
    #[error("provider adapter state is inconsistent: {0}")]
    AdapterState(&'static str),
    #[error("workspace admission is durably rejected")]
    AdmissionRejected,
    #[error("workspace execution was aborted by cancellation or expiry")]
    ExecutionAborted,
    #[error("activation capability bindings do not match durable authority")]
    ActivationBindingMismatch,
    #[error("activation capability is revoked")]
    ActivationRevoked,
    #[error("activation capability has already been consumed")]
    ActivationReplay,
    #[error("task-material execution receipt has already been claimed")]
    ExecutionReplay,
    #[error("provider activation has not been observed for the bound workload")]
    ActivationNotObserved,
    #[error("activation capability is expired")]
    ActivationExpired,
    #[error("local process I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("terminal record serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, ControllerError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Scope {
    Agent(String),
    Tenant(String),
    Issuer(String),
}

impl Scope {
    fn parts(&self) -> (&'static str, &str) {
        match self {
            Self::Agent(id) => ("agent", id),
            Self::Tenant(id) => ("tenant", id),
            Self::Issuer(id) => ("issuer", id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Prepared,
    Admitted,
    Creating,
    Active,
    Terminal,
    Cleaning,
    Cleaned,
    Rejected,
    Cancelled,
    Expired,
    RecoveryError,
}

impl Lifecycle {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Admitted => "admitted",
            Self::Creating => "creating",
            Self::Active => "active",
            Self::Terminal => "terminal",
            Self::Cleaning => "cleaning",
            Self::Cleaned => "cleaned",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::RecoveryError => "recovery_error",
        }
    }

    fn allows(self, next: Self) -> bool {
        use Lifecycle::*;
        matches!(
            (self, next),
            (Prepared, Admitted | Rejected | Expired | Cancelled)
                | (Admitted, Creating | Cancelled | Expired | RecoveryError)
                | (Creating, Active | Cancelled | Expired | RecoveryError)
                | (Active, Terminal | Cancelled | Expired | RecoveryError)
                | (Terminal, Cleaning | RecoveryError)
                | (Cancelled, Cleaning | RecoveryError)
                | (Expired, Cleaning | RecoveryError)
                | (Cleaning, Cleaned | RecoveryError)
                | (
                    RecoveryError,
                    Creating | Active | Terminal | Cancelled | Expired | Cleaning
                )
        )
    }
}

impl std::fmt::Display for Lifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Lifecycle {
    type Err = ControllerError;

    fn from_str(value: &str) -> Result<Self> {
        Ok(match value {
            "prepared" => Self::Prepared,
            "admitted" => Self::Admitted,
            "creating" => Self::Creating,
            "active" => Self::Active,
            "terminal" => Self::Terminal,
            "cleaning" => Self::Cleaning,
            "cleaned" => Self::Cleaned,
            "rejected" => Self::Rejected,
            "cancelled" => Self::Cancelled,
            "expired" => Self::Expired,
            "recovery_error" => Self::RecoveryError,
            other => return Err(ControllerError::CorruptState(other.to_owned())),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub session_id: String,
    pub jti: String,
    pub capability_digest: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub scope: Scope,
    pub signed_max_concurrency: u32,
    pub deployment_max_concurrency: u32,
    pub artifact_limit_bytes: u64,
    pub expires_at: i64,
}

impl AdmissionRequest {
    fn validate(&self) -> Result<()> {
        if self.session_id.is_empty()
            || self.jti.is_empty()
            || self.capability_digest.is_empty()
            || self.owner_id.is_empty()
            || self.workspace_id.is_empty()
            || self.scope.parts().1.is_empty()
        {
            return Err(ControllerError::InvalidRequest(
                "identifiers must be non-empty",
            ));
        }
        if self.signed_max_concurrency == 0 || self.deployment_max_concurrency == 0 {
            return Err(ControllerError::InvalidRequest(
                "concurrency limits must be positive",
            ));
        }
        if self.artifact_limit_bytes == 0 {
            return Err(ControllerError::InvalidRequest(
                "artifact limit must be positive",
            ));
        }
        sqlite_i64(self.artifact_limit_bytes)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOutcome {
    Admitted,
    Existing(Lifecycle),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub transfer_receipt_digest: String,
    pub bytes: u64,
}

impl Artifact {
    pub fn new(path: impl Into<String>, sha256: impl Into<String>, bytes: u64) -> Self {
        let sha256 = sha256.into();
        Self {
            path: path.into(),
            transfer_receipt_digest: sha256.clone(),
            sha256,
            bytes,
        }
    }

    fn normalized_path(&self) -> Result<String> {
        let normalized = self.path.replace('\\', "/");
        if normalized.is_empty()
            || normalized.starts_with('/')
            || normalized
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || self.bytes == 0
            || self.sha256.len() != 64
            || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.transfer_receipt_digest.len() != 64
            || !self
                .transfer_receipt_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ControllerError::InvalidArtifact);
        }
        sqlite_i64(self.bytes).map_err(|_| ControllerError::InvalidArtifact)?;
        Ok(normalized)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Accepted,
    Rejected,
}

impl Decision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalReceipt {
    pub receipt_digest: String,
    pub result_digest: String,
    pub transfer_receipt_digests: Vec<String>,
    pub session_id: String,
    pub decision: Decision,
    pub artifact_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct Ledger {
    path: PathBuf,
}

fn add_column_if_missing(
    conn: &Connection,
    table: &'static str,
    column: &'static str,
    definition: &'static str,
) -> Result<()> {
    let pragma = match table {
        "sessions" => "PRAGMA table_info(sessions)",
        "launch_authorizations" => "PRAGMA table_info(launch_authorizations)",
        _ => {
            return Err(ControllerError::InvalidRequest(
                "unsupported migration table",
            ))
        }
    };
    let present = conn
        .prepare(pragma)?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?
        .iter()
        .any(|existing| existing == column);
    if present {
        return Ok(());
    }
    let statement = match (table, column, definition) {
        ("sessions", "provider_uid", "TEXT") => {
            "ALTER TABLE sessions ADD COLUMN provider_uid TEXT"
        }
        ("sessions", "provider_generation", "INTEGER") => {
            "ALTER TABLE sessions ADD COLUMN provider_generation INTEGER"
        }
        ("sessions", "authority_version", "INTEGER NOT NULL DEFAULT 0") => {
            "ALTER TABLE sessions ADD COLUMN authority_version INTEGER NOT NULL DEFAULT 0"
        }
        ("launch_authorizations", "execution_spec_digest", "TEXT NOT NULL DEFAULT ''") => {
            "ALTER TABLE launch_authorizations ADD COLUMN execution_spec_digest TEXT NOT NULL DEFAULT ''"
        }
        ("launch_authorizations", "execution_spec_json", "TEXT NOT NULL DEFAULT ''") => {
            "ALTER TABLE launch_authorizations ADD COLUMN execution_spec_json TEXT NOT NULL DEFAULT ''"
        }
        ("launch_authorizations", "consumer_boot_id", "TEXT") => {
            "ALTER TABLE launch_authorizations ADD COLUMN consumer_boot_id TEXT"
        }
        ("launch_authorizations", "provider_execution_claim_token", "TEXT") => {
            "ALTER TABLE launch_authorizations ADD COLUMN provider_execution_claim_token TEXT"
        }
        ("launch_authorizations", "material_receipt_token", "TEXT") => {
            "ALTER TABLE launch_authorizations ADD COLUMN material_receipt_token TEXT"
        }
        ("launch_authorizations", "execution_status", "TEXT NOT NULL DEFAULT 'unclaimed'") => {
            "ALTER TABLE launch_authorizations ADD COLUMN execution_status TEXT NOT NULL DEFAULT 'unclaimed'"
        }
        _ => return Err(ControllerError::InvalidRequest("unsupported migration column")),
    };
    conn.execute(statement, [])?;
    Ok(())
}

impl Ledger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| ControllerError::InvalidRequest("cannot create ledger directory"))?;
        }
        let ledger = Self { path };
        let deadline = std::time::Instant::now() + BUSY_TIMEOUT;
        loop {
            match ledger.initialize() {
                Ok(()) => break,
                Err(ControllerError::Sqlite(error))
                    if is_busy_or_locked(&error) && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(ledger)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.connection()?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS controller_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                version INTEGER NOT NULL CHECK(version > 0)
            );
            INSERT INTO controller_schema(singleton, version) VALUES (1, 4)
                ON CONFLICT(singleton) DO NOTHING;
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                jti TEXT NOT NULL UNIQUE,
                capability_digest TEXT NOT NULL UNIQUE,
                owner_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL UNIQUE,
                provider_uid TEXT UNIQUE,
                provider_generation INTEGER,
                authority_version INTEGER NOT NULL DEFAULT 4 CHECK(authority_version >= 0),
                scope_kind TEXT NOT NULL CHECK(scope_kind IN ('agent','tenant','issuer')),
                scope_id TEXT NOT NULL,
                signed_max_concurrency INTEGER NOT NULL CHECK(signed_max_concurrency > 0),
                deployment_max_concurrency INTEGER NOT NULL CHECK(deployment_max_concurrency > 0),
                artifact_limit_bytes INTEGER NOT NULL CHECK(artifact_limit_bytes > 0),
                artifact_bytes INTEGER NOT NULL DEFAULT 0 CHECK(artifact_bytes >= 0),
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN (
                    'prepared','admitted','creating','active','terminal','cleaning','cleaned',
                    'rejected','cancelled','expired','recovery_error'
                )),
                reserved INTEGER NOT NULL DEFAULT 0 CHECK(reserved IN (0,1)),
                cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancellation_requested IN (0,1)),
                terminal_decision TEXT CHECK(terminal_decision IN ('accepted','rejected')),
                terminal_receipt_digest TEXT UNIQUE,
                terminal_result_digest TEXT,
                terminal_transfer_digest_set TEXT,
                cleanup_claim TEXT,
                launch_epoch INTEGER NOT NULL DEFAULT 0 CHECK(launch_epoch >= 0),
                last_error TEXT,
                version INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL DEFAULT(unixepoch()),
                updated_at INTEGER NOT NULL DEFAULT(unixepoch())
            );
            CREATE INDEX IF NOT EXISTS sessions_scope_reservation
                ON sessions(scope_kind, scope_id, reserved);
            CREATE TABLE IF NOT EXISTS artifacts (
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                transfer_receipt_digest TEXT NOT NULL UNIQUE,
                bytes INTEGER NOT NULL CHECK(bytes > 0),
                PRIMARY KEY(session_id, path)
            );
            CREATE TABLE IF NOT EXISTS transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
                from_state TEXT,
                to_state TEXT NOT NULL,
                event TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT(unixepoch())
            );
            CREATE TABLE IF NOT EXISTS launch_authorizations (
                session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
                launch_epoch INTEGER NOT NULL CHECK(launch_epoch > 0),
                activation_token TEXT NOT NULL UNIQUE,
                workspace_id TEXT NOT NULL,
                provider_uid TEXT NOT NULL,
                provider_generation INTEGER NOT NULL,
                task_input_digest TEXT NOT NULL,
                execution_spec_digest TEXT NOT NULL,
                execution_spec_json TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('issued','redeemed','revoked')),
                consumer_boot_id TEXT,
                provider_execution_claim_token TEXT,
                material_receipt_token TEXT,
                execution_status TEXT NOT NULL DEFAULT 'unclaimed'
                    CHECK(execution_status IN ('unclaimed','claimed')),
                issued_at INTEGER NOT NULL,
                redeemed_at INTEGER,
                revoked_at INTEGER,
                PRIMARY KEY(session_id, launch_epoch)
            );
            "#,
        )?;
        let has_launch_epoch = conn
            .prepare("PRAGMA table_info(sessions)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .iter()
            .any(|column| column == "launch_epoch");
        if !has_launch_epoch {
            conn.execute(
                "ALTER TABLE sessions ADD COLUMN launch_epoch INTEGER NOT NULL DEFAULT 0 CHECK(launch_epoch >= 0)",
                [],
            )?;
        }
        add_column_if_missing(&conn, "sessions", "provider_uid", "TEXT")?;
        add_column_if_missing(&conn, "sessions", "provider_generation", "INTEGER")?;
        add_column_if_missing(
            &conn,
            "sessions",
            "authority_version",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        add_column_if_missing(
            &conn,
            "launch_authorizations",
            "execution_spec_digest",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        add_column_if_missing(
            &conn,
            "launch_authorizations",
            "execution_spec_json",
            "TEXT NOT NULL DEFAULT ''",
        )?;
        add_column_if_missing(&conn, "launch_authorizations", "consumer_boot_id", "TEXT")?;
        add_column_if_missing(
            &conn,
            "launch_authorizations",
            "provider_execution_claim_token",
            "TEXT",
        )?;
        add_column_if_missing(
            &conn,
            "launch_authorizations",
            "material_receipt_token",
            "TEXT",
        )?;
        add_column_if_missing(
            &conn,
            "launch_authorizations",
            "execution_status",
            "TEXT NOT NULL DEFAULT 'unclaimed'",
        )?;
        conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_launch_material_receipt
             ON launch_authorizations(material_receipt_token)
             WHERE material_receipt_token IS NOT NULL;",
        )?;
        conn.execute_batch(
            "BEGIN IMMEDIATE;
             INSERT INTO transitions(session_id,from_state,to_state,event)
             SELECT session_id,state,'recovery_error','schema-v4-legacy-authority-quarantine'
             FROM sessions
             WHERE authority_version < 4
               AND (SELECT version FROM controller_schema WHERE singleton=1) < 4
               AND state NOT IN ('cleaned','rejected','recovery_error');
             UPDATE sessions
             SET state='recovery_error',cancellation_requested=1,
                 last_error='legacy-authority-quarantined',version=version+1,
                 updated_at=unixepoch()
             WHERE authority_version < 4
               AND (SELECT version FROM controller_schema WHERE singleton=1) < 4
               AND state NOT IN ('cleaned','rejected');
             UPDATE launch_authorizations
             SET status='revoked',revoked_at=COALESCE(revoked_at,unixepoch())
             WHERE status='issued'
               AND session_id IN (
                   SELECT session_id FROM sessions WHERE authority_version < 4
               );
             UPDATE controller_schema SET version=4 WHERE singleton=1 AND version < 4;
             COMMIT;",
        )?;
        Ok(())
    }

    fn connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn)
    }

    pub fn journal_mode(&self) -> Result<String> {
        let conn = self.connection()?;
        Ok(conn.pragma_query_value(None, "journal_mode", |row| row.get(0))?)
    }

    pub fn schema_version(&self) -> Result<u32> {
        let conn = self.connection()?;
        Ok(conn.query_row(
            "SELECT version FROM controller_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }

    pub const fn session_job_quota() -> u32 {
        1
    }

    pub fn prepare(&self, request: &AdmissionRequest) -> Result<AdmissionOutcome> {
        request.validate()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = prepare_in_tx(&tx, request);
        if result.is_ok() {
            tx.commit()?;
        }
        result
    }

    pub fn admit(&self, session_id: &str) -> Result<AdmissionOutcome> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = admit_in_tx(&tx, session_id);
        if matches!(
            &result,
            Ok(_) | Err(ControllerError::CapacityExceeded { .. })
        ) {
            tx.commit()?;
        }
        result
    }

    pub fn prepare_and_admit(&self, request: &AdmissionRequest) -> Result<AdmissionOutcome> {
        request.validate()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = match prepare_in_tx(&tx, request) {
            Ok(AdmissionOutcome::Existing(Lifecycle::Prepared)) => {
                admit_in_tx(&tx, &request.session_id)
            }
            other => other,
        };
        if matches!(
            &result,
            Ok(_) | Err(ControllerError::CapacityExceeded { .. })
        ) {
            tx.commit()?;
        }
        result
    }

    pub fn state(&self, session_id: &str) -> Result<Lifecycle> {
        let conn = self.connection()?;
        state_from_connection(&conn, session_id)
    }

    pub fn expires_at(&self, session_id: &str) -> Result<i64> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT expires_at FROM sessions WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ControllerError::SessionNotFound)
    }

    fn transition(&self, session_id: &str, next: Lifecycle, event: &str) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transition_in_tx(&tx, session_id, next, event, None)?;
        tx.commit()?;
        Ok(())
    }

    pub fn reservation_count(&self, scope: &Scope) -> Result<u32> {
        let conn = self.connection()?;
        let (kind, id) = scope.parts();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE scope_kind=?1 AND scope_id=?2 AND reserved=1",
            params![kind, id],
            |row| row.get(0),
        )?)
    }

    pub fn record_artifact(&self, session_id: &str, artifact: &Artifact) -> Result<()> {
        let normalized_path = artifact.normalized_path()?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, used, limit): (String, i64, i64) = tx
            .query_row(
                "SELECT state,artifact_bytes,artifact_limit_bytes FROM sessions WHERE session_id=?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if Lifecycle::from_str(&state)? != Lifecycle::Active {
            return Err(ControllerError::InvalidTransition {
                from: Lifecycle::from_str(&state)?,
                to: Lifecycle::Terminal,
            });
        }
        let artifact_bytes = sqlite_i64(artifact.bytes)?;
        let duplicate = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM artifacts WHERE session_id=?1 AND path=?2)",
            params![session_id, normalized_path],
            |row| row.get::<_, bool>(0),
        )?;
        if duplicate {
            return Err(ControllerError::DuplicateArtifact);
        }
        if artifact_bytes > limit.saturating_sub(used) {
            return Err(ControllerError::ArtifactLimitExceeded);
        }
        tx.execute(
            "INSERT INTO artifacts(session_id,path,sha256,transfer_receipt_digest,bytes) VALUES (?1,?2,?3,?4,?5)",
            params![
                session_id,
                normalized_path,
                artifact.sha256,
                artifact.transfer_receipt_digest,
                artifact_bytes
            ],
        )
        .map_err(|error| {
            if is_unique_constraint(&error) {
                ControllerError::DuplicateArtifact
            } else {
                ControllerError::Sqlite(error)
            }
        })?;
        tx.execute(
            "UPDATE sessions SET artifact_bytes=artifact_bytes+?2,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
            params![session_id, artifact_bytes],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_terminal(&self, receipt: &TerminalReceipt) -> Result<()> {
        if !is_sha256(&receipt.receipt_digest)
            || !is_sha256(&receipt.result_digest)
            || receipt
                .transfer_receipt_digests
                .iter()
                .any(|digest| !is_sha256(digest))
        {
            return Err(ControllerError::TerminalReceiptMismatch);
        }
        let mut claimed_transfers = receipt.transfer_receipt_digests.clone();
        claimed_transfers.sort();
        if claimed_transfers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ControllerError::TerminalReceiptMismatch);
        }
        let transfer_digest_set = serde_json::to_string(&claimed_transfers)?;
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (
            state,
            artifact_bytes,
            prior_receipt,
            prior_decision,
            prior_result,
            prior_transfers,
            cancellation_requested,
        ): TerminalSessionRow = tx
            .query_row(
                "SELECT state,artifact_bytes,terminal_receipt_digest,terminal_decision,
                        terminal_result_digest,terminal_transfer_digest_set,cancellation_requested
                 FROM sessions WHERE session_id=?1",
                [&receipt.session_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if let Some(prior) = prior_receipt {
            if prior == receipt.receipt_digest
                && prior_decision.as_deref() == Some(receipt.decision.as_str())
                && artifact_bytes == sqlite_i64(receipt.artifact_bytes)?
                && prior_result.as_deref() == Some(&receipt.result_digest)
                && prior_transfers.as_deref() == Some(&transfer_digest_set)
            {
                tx.commit()?;
                return Ok(());
            }
            if prior == receipt.receipt_digest {
                return Err(ControllerError::TerminalReceiptMismatch);
            }
            return Err(ControllerError::ReceiptReplay);
        }
        if cancellation_requested != 0 {
            return Err(ControllerError::ExecutionAborted);
        }
        if artifact_bytes != sqlite_i64(receipt.artifact_bytes)? {
            return Err(ControllerError::TerminalReceiptMismatch);
        }
        let mut persisted_transfers = tx
            .prepare(
                "SELECT transfer_receipt_digest FROM artifacts WHERE session_id=?1 ORDER BY transfer_receipt_digest",
            )?
            .query_map([&receipt.session_id], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        persisted_transfers.sort();
        if persisted_transfers != claimed_transfers {
            return Err(ControllerError::TerminalReceiptMismatch);
        }
        let current = Lifecycle::from_str(&state)?;
        if !current.allows(Lifecycle::Terminal) {
            return Err(ControllerError::InvalidTransition {
                from: current,
                to: Lifecycle::Terminal,
            });
        }
        tx.execute(
            "UPDATE sessions SET state='terminal',terminal_decision=?2,terminal_receipt_digest=?3,
                terminal_result_digest=?4,terminal_transfer_digest_set=?5,
                version=version+1,updated_at=unixepoch() WHERE session_id=?1",
            params![
                receipt.session_id,
                receipt.decision.as_str(),
                receipt.receipt_digest,
                receipt.result_digest,
                transfer_digest_set,
            ],
        )
        .map_err(|error| {
            if is_unique_constraint(&error) {
                ControllerError::ReceiptReplay
            } else {
                ControllerError::Sqlite(error)
            }
        })?;
        insert_transition(
            &tx,
            &receipt.session_id,
            Some(current),
            Lifecycle::Terminal,
            "terminal-receipt",
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn begin_cleanup(
        &self,
        session_id: &str,
        owner_id: &str,
        workspace_id: &str,
        claim: &str,
    ) -> Result<()> {
        if claim.is_empty() {
            return Err(ControllerError::InvalidRequest(
                "cleanup claim must be non-empty",
            ));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (owner, workspace, state, existing_claim): (String, String, String, Option<String>) = tx
            .query_row(
                "SELECT owner_id,workspace_id,state,cleanup_claim FROM sessions WHERE session_id=?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if owner != owner_id || workspace != workspace_id {
            return Err(ControllerError::OwnershipMismatch);
        }
        let current = Lifecycle::from_str(&state)?;
        if current == Lifecycle::Cleaning || current == Lifecycle::Cleaned {
            if existing_claim.as_deref() == Some(claim) {
                tx.commit()?;
                return Ok(());
            }
            return Err(ControllerError::CleanupClaimMismatch);
        }
        if !current.allows(Lifecycle::Cleaning) {
            return Err(ControllerError::InvalidTransition {
                from: current,
                to: Lifecycle::Cleaning,
            });
        }
        tx.execute(
            "UPDATE sessions SET state='cleaning',cleanup_claim=?2,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
            params![session_id, claim],
        )?;
        insert_transition(
            &tx,
            session_id,
            Some(current),
            Lifecycle::Cleaning,
            "cleanup-claim",
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_cleaned(&self, session_id: &str, claim: &str) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, existing_claim): (String, Option<String>) = tx
            .query_row(
                "SELECT state,cleanup_claim FROM sessions WHERE session_id=?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if existing_claim.as_deref() != Some(claim) {
            return Err(ControllerError::CleanupClaimMismatch);
        }
        let current = Lifecycle::from_str(&state)?;
        if current == Lifecycle::Cleaned {
            tx.commit()?;
            return Ok(());
        }
        if !current.allows(Lifecycle::Cleaned) {
            return Err(ControllerError::InvalidTransition {
                from: current,
                to: Lifecycle::Cleaned,
            });
        }
        tx.execute(
            "UPDATE sessions SET state='cleaned',reserved=0,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
            [session_id],
        )?;
        insert_transition(
            &tx,
            session_id,
            Some(current),
            Lifecycle::Cleaned,
            "cleanup-complete",
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn request_cancellation(&self, session_id: &str, reason: &str) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = state_from_transaction(&tx, session_id)?;
        if current == Lifecycle::Cancelled {
            revoke_issued_in_tx(&tx, session_id)?;
            tx.commit()?;
            return Ok(());
        }
        if !current.allows(Lifecycle::Cancelled) {
            return Err(ControllerError::InvalidTransition {
                from: current,
                to: Lifecycle::Cancelled,
            });
        }
        tx.execute(
            "UPDATE sessions SET state='cancelled',cancellation_requested=1,last_error=?2,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
            params![session_id, reason],
        )?;
        insert_transition(
            &tx,
            session_id,
            Some(current),
            Lifecycle::Cancelled,
            "cancel",
        )?;
        revoke_issued_in_tx(&tx, session_id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn cancellation_requested(&self, session_id: &str) -> Result<bool> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT cancellation_requested FROM sessions WHERE session_id=?1",
            [session_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|value| value != 0)
        .ok_or(ControllerError::SessionNotFound)
    }

    pub fn mark_expired(&self, session_id: &str) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transition_in_tx(&tx, session_id, Lifecycle::Expired, "expire", None)?;
        revoke_issued_in_tx(&tx, session_id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn reject(&self, session_id: &str, reason: &str) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = state_from_transaction(&tx, session_id)?;
        if current != Lifecycle::Prepared {
            return Err(ControllerError::InvalidTransition {
                from: current,
                to: Lifecycle::Rejected,
            });
        }
        tx.execute(
            "UPDATE sessions SET state='rejected',last_error=?2,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
            params![session_id, reason],
        )?;
        insert_transition(
            &tx,
            session_id,
            Some(current),
            Lifecycle::Rejected,
            "reject",
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_recovery_error(&self, session_id: &str, reason: &str) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = state_from_transaction(&tx, session_id)?;
        if matches!(
            current,
            Lifecycle::Terminal | Lifecycle::Cancelled | Lifecycle::Expired
        ) {
            tx.execute(
                "UPDATE sessions SET last_error=?2,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
                params![session_id, reason],
            )?;
            tx.commit()?;
            return Ok(());
        }
        if !current.allows(Lifecycle::RecoveryError) {
            return Err(ControllerError::InvalidTransition {
                from: current,
                to: Lifecycle::RecoveryError,
            });
        }
        tx.execute(
            "UPDATE sessions SET state='recovery_error',last_error=?2,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
            params![session_id, reason],
        )?;
        insert_transition(
            &tx,
            session_id,
            Some(current),
            Lifecycle::RecoveryError,
            "recovery-error",
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn prepare_in_tx(tx: &Transaction<'_>, request: &AdmissionRequest) -> Result<AdmissionOutcome> {
    if let Some(outcome) = existing_or_conflict(tx, request)? {
        return Ok(outcome);
    }
    let (scope_kind, scope_id) = request.scope.parts();
    let artifact_limit = sqlite_i64(request.artifact_limit_bytes)?;
    tx.execute(
        "INSERT INTO sessions (
            session_id,jti,capability_digest,owner_id,workspace_id,scope_kind,scope_id,
            signed_max_concurrency,deployment_max_concurrency,artifact_limit_bytes,expires_at,
            state,authority_version
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'prepared',4)",
        params![
            request.session_id,
            request.jti,
            request.capability_digest,
            request.owner_id,
            request.workspace_id,
            scope_kind,
            scope_id,
            request.signed_max_concurrency,
            request.deployment_max_concurrency,
            artifact_limit,
            request.expires_at,
        ],
    )
    .map_err(map_unique_constraint)?;
    insert_transition(
        tx,
        &request.session_id,
        None,
        Lifecycle::Prepared,
        "prepare",
    )?;
    Ok(AdmissionOutcome::Existing(Lifecycle::Prepared))
}

fn admit_in_tx(tx: &Transaction<'_>, session_id: &str) -> Result<AdmissionOutcome> {
    let row = session_row(tx, session_id)?;
    if row.state != Lifecycle::Prepared {
        return Ok(AdmissionOutcome::Existing(row.state));
    }
    let incoming_limit = min(row.signed_max, row.deployment_max);
    let (active, existing_limit): (u32, Option<u32>) = tx.query_row(
        "SELECT COUNT(*),
                MIN(CASE WHEN signed_max_concurrency < deployment_max_concurrency
                         THEN signed_max_concurrency ELSE deployment_max_concurrency END)
         FROM sessions
         WHERE scope_kind=?1 AND scope_id=?2 AND reserved=1",
        params![row.scope_kind, row.scope_id],
        |query| Ok((query.get(0)?, query.get(1)?)),
    )?;
    let limit = min(incoming_limit, existing_limit.unwrap_or(incoming_limit));
    if active >= limit {
        transition_in_tx(
            tx,
            session_id,
            Lifecycle::Rejected,
            "capacity-rejected",
            Some(false),
        )?;
        return Err(ControllerError::CapacityExceeded { active, limit });
    }
    transition_in_tx(tx, session_id, Lifecycle::Admitted, "admit", Some(true))?;
    Ok(AdmissionOutcome::Admitted)
}

#[derive(Debug)]
struct SessionRow {
    state: Lifecycle,
    scope_kind: String,
    scope_id: String,
    signed_max: u32,
    deployment_max: u32,
}

fn session_row(tx: &Transaction<'_>, session_id: &str) -> Result<SessionRow> {
    let row: Option<(String, String, String, u32, u32)> = tx
        .query_row(
            "SELECT state,scope_kind,scope_id,signed_max_concurrency,deployment_max_concurrency FROM sessions WHERE session_id=?1",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let (state, scope_kind, scope_id, signed_max, deployment_max) =
        row.ok_or(ControllerError::SessionNotFound)?;
    Ok(SessionRow {
        state: Lifecycle::from_str(&state)?,
        scope_kind,
        scope_id,
        signed_max,
        deployment_max,
    })
}

type ExistingSession = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    u32,
    u32,
    i64,
    i64,
);

fn existing_or_conflict(
    tx: &Transaction<'_>,
    request: &AdmissionRequest,
) -> Result<Option<AdmissionOutcome>> {
    let existing: Option<ExistingSession> = tx
        .query_row(
            "SELECT state,jti,capability_digest,owner_id,workspace_id,scope_kind,scope_id,
                    signed_max_concurrency,deployment_max_concurrency,artifact_limit_bytes,expires_at
             FROM sessions WHERE session_id=?1",
            [&request.session_id],
            |row| {
                Ok((
                    row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?,
                    row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?,
                ))
            },
        )
        .optional()?;
    if let Some((
        state,
        jti,
        digest,
        owner,
        workspace,
        kind,
        scope_id,
        signed,
        deployment,
        artifact_limit,
        expires,
    )) = existing
    {
        let (expected_kind, expected_scope) = request.scope.parts();
        if jti == request.jti
            && digest == request.capability_digest
            && owner == request.owner_id
            && workspace == request.workspace_id
            && kind == expected_kind
            && scope_id == expected_scope
            && signed == request.signed_max_concurrency
            && deployment == request.deployment_max_concurrency
            && artifact_limit == sqlite_i64(request.artifact_limit_bytes)?
            && expires == request.expires_at
        {
            return Ok(Some(AdmissionOutcome::Existing(Lifecycle::from_str(
                &state,
            )?)));
        }
        return Err(ControllerError::SessionConflict);
    }
    if tx
        .query_row(
            "SELECT 1 FROM sessions WHERE jti=?1",
            [&request.jti],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(ControllerError::JtiReplay);
    }
    if tx
        .query_row(
            "SELECT 1 FROM sessions WHERE capability_digest=?1",
            [&request.capability_digest],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(ControllerError::CapabilityReplay);
    }
    if tx
        .query_row(
            "SELECT 1 FROM sessions WHERE workspace_id=?1",
            [&request.workspace_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Err(ControllerError::WorkspaceOwned);
    }
    Ok(None)
}

fn transition_in_tx(
    tx: &Transaction<'_>,
    session_id: &str,
    next: Lifecycle,
    event: &str,
    reserve: Option<bool>,
) -> Result<()> {
    let current = state_from_transaction(tx, session_id)?;
    if current == next {
        return Ok(());
    }
    if !current.allows(next) {
        return Err(ControllerError::InvalidTransition {
            from: current,
            to: next,
        });
    }
    match reserve {
        Some(value) => {
            tx.execute(
                "UPDATE sessions SET state=?2,reserved=?3,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
                params![session_id, next.as_str(), i64::from(value)],
            )?;
        }
        None => {
            tx.execute(
                "UPDATE sessions SET state=?2,version=version+1,updated_at=unixepoch() WHERE session_id=?1",
                params![session_id, next.as_str()],
            )?;
        }
    }
    insert_transition(tx, session_id, Some(current), next, event)?;
    Ok(())
}

fn insert_transition(
    tx: &Transaction<'_>,
    session_id: &str,
    from: Option<Lifecycle>,
    to: Lifecycle,
    event: &str,
) -> Result<()> {
    tx.execute(
        "INSERT INTO transitions(session_id,from_state,to_state,event) VALUES (?1,?2,?3,?4)",
        params![session_id, from.map(Lifecycle::as_str), to.as_str(), event],
    )?;
    Ok(())
}

fn revoke_issued_in_tx(tx: &Transaction<'_>, session_id: &str) -> Result<()> {
    tx.execute(
        "UPDATE launch_authorizations
         SET status='revoked',revoked_at=unixepoch()
         WHERE session_id=?1 AND status='issued'",
        [session_id],
    )?;
    Ok(())
}

fn state_from_connection(conn: &Connection, session_id: &str) -> Result<Lifecycle> {
    let state: Option<String> = conn
        .query_row(
            "SELECT state FROM sessions WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()?;
    Lifecycle::from_str(&state.ok_or(ControllerError::SessionNotFound)?)
}

fn state_from_transaction(tx: &Transaction<'_>, session_id: &str) -> Result<Lifecycle> {
    let state: Option<String> = tx
        .query_row(
            "SELECT state FROM sessions WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()?;
    Lifecycle::from_str(&state.ok_or(ControllerError::SessionNotFound)?)
}

fn is_busy_or_locked(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if matches!(
                inner.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    )
}

fn is_unique_constraint(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                || inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
    )
}

fn map_unique_constraint(error: rusqlite::Error) -> ControllerError {
    if is_unique_constraint(&error) {
        ControllerError::SessionConflict
    } else {
        ControllerError::Sqlite(error)
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sqlite_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| ControllerError::InvalidRequest("byte count exceeds SQLite range"))
}

/// Canonical material that one activation capability authorizes for execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionSpec {
    program: String,
    args: Vec<String>,
    environment: Vec<(String, String)>,
    task_input_digest: String,
    credential_handle_digests: Vec<String>,
}

impl ExecutionSpec {
    /// Builds a spec with no delegated environment or credential handles.
    pub fn new(
        program: impl Into<String>,
        args: Vec<String>,
        task_input_digest: impl Into<String>,
    ) -> Result<Self> {
        Self::with_bindings(program, args, Vec::new(), task_input_digest, Vec::new())
    }

    /// Builds and canonicalizes every piece of material released to the worker.
    pub fn with_bindings(
        program: impl Into<String>,
        args: Vec<String>,
        mut environment: Vec<(String, String)>,
        task_input_digest: impl Into<String>,
        mut credential_handle_digests: Vec<String>,
    ) -> Result<Self> {
        let program = program.into();
        let task_input_digest = task_input_digest.into();
        if program.is_empty()
            || !Path::new(&program).is_absolute()
            || program.contains('\0')
            || args.iter().any(|arg| arg.contains('\0'))
            || !is_sha256(&task_input_digest)
            || environment.iter().any(|(key, value)| {
                key.is_empty() || key.contains(['=', '\0']) || value.contains('\0')
            })
            || credential_handle_digests
                .iter()
                .any(|digest| !is_sha256(digest))
        {
            return Err(ControllerError::InvalidRequest("invalid execution spec"));
        }
        environment.sort();
        if environment.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(ControllerError::InvalidRequest(
                "duplicate execution environment key",
            ));
        }
        credential_handle_digests.sort();
        credential_handle_digests.dedup();
        Ok(Self {
            program,
            args,
            environment,
            task_input_digest,
            credential_handle_digests,
        })
    }

    fn digest(&self) -> Result<String> {
        let encoded = serde_json::to_vec(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"buzz-local-execution-spec-v1\0");
        hasher.update((encoded.len() as u64).to_le_bytes());
        hasher.update(encoded);
        Ok(hex::encode(hasher.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub session_id: String,
    pub owner_id: String,
    pub workspace_id: String,
    pub capability_digest: String,
    pub provider_scope: String,
    pub create_operation_key: String,
    pub delete_operation_key: String,
    pub provider_uid: String,
    pub provider_generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Single-use authorization bound to one exact inert provider workload.
pub struct ActivationCapability {
    pub token: String,
    pub session_id: String,
    pub workspace_id: String,
    pub provider_uid: String,
    pub provider_generation: i64,
    pub task_input_digest: String,
    pub execution_spec_digest: String,
    pub expires_at: i64,
    pub launch_epoch: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Opaque durable receipt for one exact worker execution claim.
pub struct TaskMaterialGrant {
    session_id: String,
    workspace_id: String,
    provider_uid: String,
    provider_generation: i64,
    launch_epoch: i64,
    expires_at: i64,
    consumer_boot_id: String,
    provider_execution_claim_token: String,
    material_receipt_token: String,
    execution_spec_digest: String,
    execution_spec: ExecutionSpec,
}

impl ActivationCapability {
    fn binding_matches(&self, identity: &SessionIdentity) -> bool {
        self.session_id == identity.session_id
            && self.workspace_id == identity.workspace_id
            && self.provider_uid == identity.provider_uid
            && self.provider_generation == identity.provider_generation
    }

    fn grant(
        &self,
        consumer_boot_id: String,
        provider_execution_claim_token: String,
        material_receipt_token: String,
        execution_spec: ExecutionSpec,
    ) -> TaskMaterialGrant {
        TaskMaterialGrant {
            session_id: self.session_id.clone(),
            workspace_id: self.workspace_id.clone(),
            provider_uid: self.provider_uid.clone(),
            provider_generation: self.provider_generation,
            launch_epoch: self.launch_epoch,
            expires_at: self.expires_at,
            consumer_boot_id,
            provider_execution_claim_token,
            material_receipt_token,
            execution_spec_digest: self.execution_spec_digest.clone(),
            execution_spec,
        }
    }
}

impl Ledger {
    pub fn identity(&self, session_id: &str) -> Result<SessionIdentity> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT session_id,owner_id,workspace_id,capability_digest,
                    provider_uid,provider_generation
             FROM sessions WHERE session_id=?1",
            [session_id],
            |row| {
                let session_id: String = row.get(0)?;
                let capability_digest: String = row.get(3)?;
                Ok(SessionIdentity {
                    owner_id: row.get(1)?,
                    workspace_id: row.get(2)?,
                    provider_scope: "fake-kubernetes".into(),
                    create_operation_key: format!("create:{capability_digest}:{session_id}"),
                    delete_operation_key: format!("delete:{capability_digest}:{session_id}"),
                    provider_uid: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    provider_generation: row.get::<_, Option<i64>>(5)?.unwrap_or_default(),
                    session_id,
                    capability_digest,
                })
            },
        )
        .optional()?
        .ok_or(ControllerError::SessionNotFound)
    }

    fn bind_provider_identity(&self, session_id: &str, binding: &ProviderBinding) -> Result<()> {
        if binding.provider_uid.is_empty() || binding.provider_generation <= 0 {
            return Err(ControllerError::AdapterState("invalid provider binding"));
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: (String, i64, Option<String>, Option<i64>) = tx
            .query_row(
                "SELECT state,cancellation_requested,provider_uid,provider_generation
                 FROM sessions WHERE session_id=?1",
                [session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if row.1 != 0 || Lifecycle::from_str(&row.0)? != Lifecycle::Creating {
            return Err(ControllerError::ExecutionAborted);
        }
        match (row.2, row.3) {
            (Some(uid), Some(generation))
                if uid == binding.provider_uid && generation == binding.provider_generation =>
            {
                tx.commit()?;
                return Ok(());
            }
            (None, None) => {}
            _ => return Err(ControllerError::OwnershipMismatch),
        }
        let updated = tx.execute(
            "UPDATE sessions SET provider_uid=?2,provider_generation=?3,version=version+1,
                                 updated_at=unixepoch()
             WHERE session_id=?1 AND provider_uid IS NULL AND provider_generation IS NULL",
            params![
                session_id,
                binding.provider_uid,
                binding.provider_generation
            ],
        )?;
        if updated != 1 {
            return Err(ControllerError::OwnershipMismatch);
        }
        tx.commit()?;
        Ok(())
    }

    pub fn cleanup_claim(&self, session_id: &str) -> Result<Option<String>> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT cleanup_claim FROM sessions WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ControllerError::SessionNotFound)
    }

    pub fn launch_epoch(&self, session_id: &str) -> Result<i64> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT launch_epoch FROM sessions WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ControllerError::SessionNotFound)
    }

    fn validate_launch(&self, capability: &ActivationCapability) -> Result<()> {
        let conn = self.connection()?;
        let row: Option<LaunchValidationRow> = conn
            .query_row(
                "SELECT s.state,s.cancellation_requested,a.activation_token,a.workspace_id,
                        a.provider_generation,a.provider_uid,a.expires_at,a.status,s.launch_epoch
                 FROM sessions s JOIN launch_authorizations a ON a.session_id=s.session_id
                 WHERE a.session_id=?1 AND a.launch_epoch=?2
                   AND a.task_input_digest=?3 AND a.execution_spec_digest=?4",
                params![
                    capability.session_id,
                    capability.launch_epoch,
                    capability.task_input_digest,
                    capability.execution_spec_digest,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((state, cancelled, token, workspace, generation, uid, expiry, status, epoch)) =
            row
        else {
            return Err(ControllerError::ActivationBindingMismatch);
        };
        if cancelled != 0
            || matches!(
                Lifecycle::from_str(&state)?,
                Lifecycle::Cancelled
                    | Lifecycle::Expired
                    | Lifecycle::Terminal
                    | Lifecycle::Cleaning
                    | Lifecycle::Cleaned
                    | Lifecycle::Rejected
            )
        {
            return Err(ControllerError::ExecutionAborted);
        }
        if token != capability.token
            || workspace != capability.workspace_id
            || generation != capability.provider_generation
            || uid != capability.provider_uid
            || expiry != capability.expires_at
            || epoch != capability.launch_epoch
        {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        match status.as_str() {
            "issued" => Ok(()),
            "redeemed" => Err(ControllerError::ActivationReplay),
            "revoked" => Err(ControllerError::ActivationRevoked),
            _ => Err(ControllerError::ActivationBindingMismatch),
        }
    }

    fn current_issued_launch(&self, session_id: &str) -> Result<Option<ActivationCapability>> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT a.activation_token,a.workspace_id,a.provider_uid,a.provider_generation,
                    a.task_input_digest,a.execution_spec_digest,a.expires_at,a.launch_epoch
             FROM launch_authorizations a JOIN sessions s ON s.session_id=a.session_id
             WHERE a.session_id=?1 AND a.launch_epoch=s.launch_epoch AND a.status='issued'",
            [session_id],
            |row| {
                Ok(ActivationCapability {
                    token: row.get(0)?,
                    session_id: session_id.to_owned(),
                    workspace_id: row.get(1)?,
                    provider_uid: row.get(2)?,
                    provider_generation: row.get(3)?,
                    task_input_digest: row.get(4)?,
                    execution_spec_digest: row.get(5)?,
                    expires_at: row.get(6)?,
                    launch_epoch: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(ControllerError::from)
    }

    fn authorize_launch(
        &self,
        session_id: &str,
        identity: &SessionIdentity,
        execution_spec: &ExecutionSpec,
        expires_at: i64,
        now: i64,
    ) -> Result<ActivationCapability> {
        let task_input_digest = &execution_spec.task_input_digest;
        let execution_spec_digest = execution_spec.digest()?;
        let execution_spec_json = serde_json::to_string(execution_spec)?;
        if identity.session_id != session_id {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, cancelled, session_expires, launch_epoch, workspace): (
            String,
            i64,
            i64,
            i64,
            String,
        ) = tx
            .query_row(
                "SELECT state,cancellation_requested,expires_at,launch_epoch,workspace_id
                 FROM sessions WHERE session_id=?1",
                [session_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if cancelled != 0
            || matches!(
                Lifecycle::from_str(&state)?,
                Lifecycle::Cancelled
                    | Lifecycle::Expired
                    | Lifecycle::Terminal
                    | Lifecycle::Cleaning
                    | Lifecycle::Cleaned
                    | Lifecycle::Rejected
            )
        {
            return Err(ControllerError::ExecutionAborted);
        }
        if Lifecycle::from_str(&state)? != Lifecycle::Creating {
            return Err(ControllerError::InvalidTransition {
                from: Lifecycle::from_str(&state)?,
                to: Lifecycle::Active,
            });
        }
        if workspace != identity.workspace_id {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        if expires_at <= now
            || expires_at > session_expires
            || expires_at.saturating_sub(now) > MAX_ACTIVATION_TTL_SECONDS
        {
            return Err(ControllerError::ActivationExpired);
        }
        if launch_epoch > 0 {
            let existing: Option<ExistingLaunchAuthorizationRow> = tx
                .query_row(
                    "SELECT activation_token,workspace_id,provider_uid,provider_generation,
                            task_input_digest,execution_spec_digest,execution_spec_json,expires_at,status
                     FROM launch_authorizations WHERE session_id=?1 AND launch_epoch=?2",
                    params![session_id, launch_epoch],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                            row.get(8)?,
                        ))
                    },
                )
                .optional()?;
            if let Some((
                token,
                bound_workspace,
                uid,
                generation,
                digest,
                spec_digest,
                spec_json,
                expiry,
                status,
            )) = existing
            {
                if status == "issued" && expiry <= now {
                    tx.execute(
                        "UPDATE launch_authorizations
                         SET status='revoked',revoked_at=?3
                         WHERE session_id=?1 AND launch_epoch=?2 AND status='issued'",
                        params![session_id, launch_epoch, now],
                    )?;
                } else if status == "issued"
                    && bound_workspace == identity.workspace_id
                    && uid == identity.provider_uid
                    && generation == identity.provider_generation
                    && digest == *task_input_digest
                    && spec_digest == execution_spec_digest
                    && spec_json == execution_spec_json
                    && expiry == expires_at
                {
                    tx.commit()?;
                    return Ok(ActivationCapability {
                        token,
                        session_id: session_id.to_owned(),
                        workspace_id: bound_workspace,
                        provider_uid: uid,
                        provider_generation: generation,
                        task_input_digest: digest,
                        execution_spec_digest: spec_digest,
                        expires_at: expiry,
                        launch_epoch,
                    });
                }
                if status == "redeemed" {
                    return Err(ControllerError::ActivationReplay);
                }
                if status != "revoked" && !(status == "issued" && expiry <= now) {
                    return Err(ControllerError::ActivationBindingMismatch);
                }
            }
        }
        let next_epoch = launch_epoch
            .checked_add(1)
            .ok_or(ControllerError::AdapterState("launch epoch exhausted"))?;
        let mut hasher = Sha256::new();
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        hasher.update(session_id.as_bytes());
        hasher.update(identity.workspace_id.as_bytes());
        hasher.update(identity.provider_uid.as_bytes());
        hasher.update(identity.provider_generation.to_le_bytes());
        hasher.update(task_input_digest.as_bytes());
        hasher.update(execution_spec_digest.as_bytes());
        hasher.update(expires_at.to_le_bytes());
        hasher.update(next_epoch.to_le_bytes());
        let token = hex::encode(hasher.finalize());
        tx.execute(
            "UPDATE sessions SET launch_epoch=?2,version=version+1,updated_at=unixepoch()
             WHERE session_id=?1",
            params![session_id, next_epoch],
        )?;
        tx.execute(
            "INSERT INTO launch_authorizations(
                session_id,launch_epoch,activation_token,workspace_id,provider_uid,
                provider_generation,task_input_digest,execution_spec_digest,execution_spec_json,
                expires_at,status,issued_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'issued',?11)",
            params![
                session_id,
                next_epoch,
                token,
                identity.workspace_id,
                identity.provider_uid,
                identity.provider_generation,
                task_input_digest,
                execution_spec_digest,
                execution_spec_json,
                expires_at,
                now,
            ],
        )?;
        tx.commit()?;
        Ok(ActivationCapability {
            token,
            session_id: session_id.to_owned(),
            workspace_id: identity.workspace_id.clone(),
            provider_uid: identity.provider_uid.clone(),
            provider_generation: identity.provider_generation,
            task_input_digest: task_input_digest.to_owned(),
            execution_spec_digest,
            expires_at,
            launch_epoch: next_epoch,
        })
    }

    fn redeem_launch(
        &self,
        capability: &ActivationCapability,
        consumer_boot_id: &str,
        provider_execution_claim_token: &str,
        execution_spec: &ExecutionSpec,
        now: i64,
    ) -> Result<TaskMaterialGrant> {
        if consumer_boot_id.is_empty()
            || consumer_boot_id.contains('\0')
            || provider_execution_claim_token.is_empty()
            || provider_execution_claim_token.contains('\0')
        {
            return Err(ControllerError::InvalidRequest(
                "consumer boot identity must be non-empty",
            ));
        }
        let spec_digest = execution_spec.digest()?;
        let spec_json = serde_json::to_string(execution_spec)?;
        if spec_digest != capability.execution_spec_digest
            || execution_spec.task_input_digest != capability.task_input_digest
        {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, cancelled, current_epoch, session_expires): (String, i64, i64, i64) = tx
            .query_row(
                "SELECT state,cancellation_requested,launch_epoch,expires_at
                 FROM sessions WHERE session_id=?1",
                [&capability.session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if cancelled != 0
            || matches!(
                Lifecycle::from_str(&state)?,
                Lifecycle::Cancelled
                    | Lifecycle::Expired
                    | Lifecycle::Terminal
                    | Lifecycle::Cleaning
                    | Lifecycle::Cleaned
                    | Lifecycle::Rejected
            )
        {
            return Err(ControllerError::ExecutionAborted);
        }
        if capability.expires_at <= now || session_expires <= now {
            return Err(ControllerError::ActivationExpired);
        }
        if current_epoch != capability.launch_epoch {
            return Err(ControllerError::ActivationRevoked);
        }
        let stored = tx
            .query_row(
                "SELECT activation_token,workspace_id,provider_uid,provider_generation,
                        task_input_digest,execution_spec_digest,execution_spec_json,expires_at,
                        status,consumer_boot_id,material_receipt_token,
                        provider_execution_claim_token
                 FROM launch_authorizations WHERE session_id=?1 AND launch_epoch=?2",
                params![capability.session_id, capability.launch_epoch],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Option<String>>(9)?,
                        row.get::<_, Option<String>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            token,
            workspace,
            uid,
            generation,
            digest,
            stored_spec_digest,
            stored_spec_json,
            expiry,
            status,
            stored_consumer,
            stored_receipt,
            stored_provider_claim,
        )) = stored
        else {
            return Err(ControllerError::ActivationRevoked);
        };
        if token != capability.token
            || workspace != capability.workspace_id
            || uid != capability.provider_uid
            || generation != capability.provider_generation
            || digest != capability.task_input_digest
            || stored_spec_digest != capability.execution_spec_digest
            || stored_spec_digest != spec_digest
            || stored_spec_json != spec_json
            || expiry != capability.expires_at
        {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        if status == "revoked" {
            return Err(ControllerError::ActivationRevoked);
        }
        if status == "redeemed" {
            if stored_consumer.as_deref() == Some(consumer_boot_id)
                && stored_provider_claim.as_deref() == Some(provider_execution_claim_token)
            {
                let receipt = stored_receipt.ok_or(ControllerError::ActivationBindingMismatch)?;
                tx.commit()?;
                return Ok(capability.grant(
                    consumer_boot_id.to_owned(),
                    provider_execution_claim_token.to_owned(),
                    receipt,
                    execution_spec.clone(),
                ));
            }
            return Err(ControllerError::ActivationReplay);
        }
        if status != "issued" {
            return Err(ControllerError::AdapterState("invalid activation status"));
        }
        let current = Lifecycle::from_str(&state)?;
        if current != Lifecycle::Creating {
            return Err(ControllerError::InvalidTransition {
                from: current,
                to: Lifecycle::Active,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(b"buzz-local-material-receipt-v1\0");
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        hasher.update(capability.token.as_bytes());
        hasher.update(consumer_boot_id.as_bytes());
        hasher.update(spec_digest.as_bytes());
        let material_receipt_token = hex::encode(hasher.finalize());
        let updated = tx.execute(
            "UPDATE launch_authorizations
             SET status='redeemed',redeemed_at=?3,consumer_boot_id=?4,
                 material_receipt_token=?5,provider_execution_claim_token=?6,
                 execution_status='unclaimed'
             WHERE session_id=?1 AND launch_epoch=?2 AND status='issued'",
            params![
                capability.session_id,
                capability.launch_epoch,
                now,
                consumer_boot_id,
                material_receipt_token,
                provider_execution_claim_token,
            ],
        )?;
        if updated != 1 {
            return Err(ControllerError::ActivationReplay);
        }
        transition_in_tx(
            &tx,
            &capability.session_id,
            Lifecycle::Active,
            "activation-redeemed",
            None,
        )?;
        tx.commit()?;
        Ok(capability.grant(
            consumer_boot_id.to_owned(),
            provider_execution_claim_token.to_owned(),
            material_receipt_token,
            execution_spec.clone(),
        ))
    }

    fn claim_and_spawn_task_material_grant<F>(
        &self,
        grant: &TaskMaterialGrant,
        before_spawn: F,
    ) -> Result<std::process::Child>
    where
        F: FnOnce(),
    {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row = tx
            .query_row(
                "SELECT s.state,s.cancellation_requested,s.workspace_id,s.launch_epoch,
                        a.provider_uid,a.provider_generation,a.expires_at,a.status,
                        a.consumer_boot_id,a.material_receipt_token,
                        a.provider_execution_claim_token,a.execution_spec_digest,
                        a.execution_spec_json,a.execution_status
                 FROM sessions s JOIN launch_authorizations a
                   ON a.session_id=s.session_id AND a.launch_epoch=s.launch_epoch
                 WHERE s.session_id=?1 AND a.status='redeemed'",
                [&grant.session_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, String>(13)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            state,
            cancelled,
            workspace,
            epoch,
            uid,
            generation,
            expiry,
            status,
            consumer,
            receipt,
            provider_execution_claim_token,
            spec_digest,
            spec_json,
            execution_status,
        )) = row
        else {
            return Err(ControllerError::ActivationRevoked);
        };
        if cancelled != 0 {
            return Err(ControllerError::ExecutionAborted);
        }
        let stored_spec: ExecutionSpec = serde_json::from_str(&spec_json)?;
        if Lifecycle::from_str(&state)? != Lifecycle::Active
            || status != "redeemed"
            || workspace != grant.workspace_id
            || epoch != grant.launch_epoch
            || uid != grant.provider_uid
            || generation != grant.provider_generation
            || expiry != grant.expires_at
            || consumer != grant.consumer_boot_id
            || receipt != grant.material_receipt_token
            || provider_execution_claim_token != grant.provider_execution_claim_token
            || spec_digest != grant.execution_spec_digest
            || stored_spec != grant.execution_spec
            || stored_spec.digest()? != spec_digest
        {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        if execution_status == "claimed" {
            return Err(ControllerError::ExecutionReplay);
        }
        if execution_status != "unclaimed" {
            return Err(ControllerError::AdapterState("invalid execution status"));
        }
        let updated = tx.execute(
            "UPDATE launch_authorizations SET execution_status='claimed'
             WHERE session_id=?1 AND launch_epoch=?2 AND material_receipt_token=?3
               AND execution_status='unclaimed'",
            params![
                grant.session_id,
                grant.launch_epoch,
                grant.material_receipt_token
            ],
        )?;
        if updated != 1 {
            return Err(ControllerError::ExecutionReplay);
        }
        before_spawn();
        let mut command = std::process::Command::new(&stored_spec.program);
        command
            .args(&stored_spec.args)
            .env_clear()
            .envs(stored_spec.environment.iter().cloned());
        configure_process_group(&mut command);
        let mut child = command.spawn()?;
        if let Err(error) = tx.commit() {
            terminate_process_tree(&mut child)?;
            return Err(ControllerError::Sqlite(error));
        }
        Ok(child)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPoint {
    AfterPrepared,
    AfterAdmitted,
    AfterCreating,
    AfterProviderCreate,
    AfterLaunchAuthorized,
    AfterProviderActivation,
    AfterActive,
    AfterTerminal,
    AfterCleaning,
    AfterProviderDelete,
    AfterCleaned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fake-provider lifecycle used to model an execution-inert creation boundary.
pub enum ProviderWorkloadState {
    Absent,
    Inert,
    Activated,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Exact provider observation used for ownership and generation fencing.
pub struct ProviderObservation {
    pub state: ProviderWorkloadState,
    pub provider_uid: String,
    pub provider_generation: i64,
    pub launch_epoch: i64,
    pub task_input_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderBinding {
    pub provider_uid: String,
    pub provider_generation: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderExecutionClaim {
    token: String,
    consumer_boot_id: String,
    execution_spec_digest: String,
}

/// Provider-neutral operations required by durable launch and cleanup recovery.
pub trait WorkspaceAdapter: Clone {
    /// Creates the exact workload in an inert, non-executing state and returns provider identity.
    fn create_owned(&self, identity: &SessionIdentity) -> Result<ProviderBinding>;
    /// Projects one exact authorization using ownership/generation preconditions.
    fn activate_owned(
        &self,
        identity: &SessionIdentity,
        capability: &ActivationCapability,
    ) -> Result<()>;
    /// Atomically claims one exact activated workload for one worker boot.
    fn claim_execution_owned(
        &self,
        identity: &SessionIdentity,
        capability: &ActivationCapability,
        consumer_boot_id: &str,
    ) -> Result<ProviderExecutionClaim>;
    /// Deletes only the exactly owned workload.
    fn delete_owned(&self, identity: &SessionIdentity) -> Result<()>;
    /// Observes exact state while rejecting ownership substitution.
    fn observe_owned(&self, identity: &SessionIdentity) -> Result<ProviderObservation>;

    fn exists_owned(&self, identity: &SessionIdentity) -> Result<bool> {
        Ok(matches!(
            self.observe_owned(identity)?.state,
            ProviderWorkloadState::Inert | ProviderWorkloadState::Activated
        ))
    }
}

#[derive(Debug, Clone)]
pub struct FakeKubernetes {
    path: PathBuf,
}

#[derive(Debug)]
struct FakeProviderRecord {
    workspace_id: String,
    capability_digest: String,
    provider_scope: String,
    create_operation_key: String,
    delete_operation_key: String,
    provider_uid: String,
    provider_generation: i64,
    present: i64,
    launch_state: String,
    activation_epoch: i64,
    activation_token: Option<String>,
    activation_task_digest: Option<String>,
    activation_spec_digest: Option<String>,
    lose_activation_response: i64,
}

impl FakeProviderRecord {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            workspace_id: row.get(0)?,
            capability_digest: row.get(1)?,
            provider_scope: row.get(2)?,
            create_operation_key: row.get(3)?,
            delete_operation_key: row.get(4)?,
            provider_uid: row.get(5)?,
            provider_generation: row.get(6)?,
            present: row.get(7)?,
            launch_state: row.get(8)?,
            activation_epoch: row.get(9)?,
            activation_token: row.get(10)?,
            activation_task_digest: row.get(11)?,
            activation_spec_digest: row.get(12)?,
            lose_activation_response: row.get(13)?,
        })
    }

    fn matches(&self, identity: &SessionIdentity) -> bool {
        self.ownership_matches(identity)
            && self.provider_uid == identity.provider_uid
            && self.provider_generation == identity.provider_generation
    }

    fn ownership_matches(&self, identity: &SessionIdentity) -> bool {
        self.workspace_id == identity.workspace_id
            && self.capability_digest == identity.capability_digest
            && self.provider_scope == identity.provider_scope
            && self.create_operation_key == identity.create_operation_key
            && self.delete_operation_key == identity.delete_operation_key
    }
}

impl FakeKubernetes {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| ControllerError::InvalidRequest("cannot create provider directory"))?;
        }
        let adapter = Self { path };
        let conn = adapter.connection()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS workloads (
                session_id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL UNIQUE,
                capability_digest TEXT NOT NULL,
                provider_scope TEXT NOT NULL,
                create_operation_key TEXT NOT NULL UNIQUE,
                delete_operation_key TEXT NOT NULL UNIQUE,
                provider_uid TEXT NOT NULL UNIQUE,
                provider_generation INTEGER NOT NULL,
                present INTEGER NOT NULL CHECK(present IN (0,1)),
                launch_state TEXT NOT NULL DEFAULT 'activated'
                    CHECK(launch_state IN ('inert','activated','deleted')),
                activation_epoch INTEGER NOT NULL DEFAULT 0,
                activation_token TEXT,
                activation_task_digest TEXT,
                activation_spec_digest TEXT,
                execution_claim_token TEXT UNIQUE,
                execution_claim_consumer TEXT,
                execution_claim_spec_digest TEXT,
                create_mutations INTEGER NOT NULL DEFAULT 0,
                activation_mutations INTEGER NOT NULL DEFAULT 0,
                execution_claim_mutations INTEGER NOT NULL DEFAULT 0,
                delete_mutations INTEGER NOT NULL DEFAULT 0,
                lose_activation_response INTEGER NOT NULL DEFAULT 0 CHECK(lose_activation_response IN (0,1)),
                updated_at INTEGER NOT NULL DEFAULT(unixepoch())
            );
            "#,
        )?;
        for (column, definition) in [
            ("launch_state", "TEXT NOT NULL DEFAULT 'activated'"),
            ("activation_epoch", "INTEGER NOT NULL DEFAULT 0"),
            ("activation_token", "TEXT"),
            ("activation_task_digest", "TEXT"),
            ("activation_spec_digest", "TEXT"),
            ("execution_claim_token", "TEXT"),
            ("execution_claim_consumer", "TEXT"),
            ("execution_claim_spec_digest", "TEXT"),
            ("activation_mutations", "INTEGER NOT NULL DEFAULT 0"),
            ("execution_claim_mutations", "INTEGER NOT NULL DEFAULT 0"),
            ("lose_activation_response", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let exists = conn
                .prepare("PRAGMA table_info(workloads)")?
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?
                .iter()
                .any(|candidate| candidate == column);
            if !exists {
                conn.execute(
                    &format!("ALTER TABLE workloads ADD COLUMN {column} {definition}"),
                    [],
                )?;
            }
        }
        Ok(adapter)
    }

    fn connection(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        Ok(conn)
    }

    pub fn workload_count(&self) -> Result<u32> {
        let conn = self.connection()?;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM workloads WHERE present=1",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn create_mutations(&self, session_id: &str) -> Result<u32> {
        self.mutation_count(session_id, "create_mutations")
    }

    pub fn delete_mutations(&self, session_id: &str) -> Result<u32> {
        self.mutation_count(session_id, "delete_mutations")
    }

    pub fn activation_mutations(&self, session_id: &str) -> Result<u32> {
        self.mutation_count(session_id, "activation_mutations")
    }

    pub fn execution_claim_mutations(&self, session_id: &str) -> Result<u32> {
        self.mutation_count(session_id, "execution_claim_mutations")
    }

    pub fn execution_claim_consumer(&self, session_id: &str) -> Result<Option<String>> {
        let conn = self.connection()?;
        conn.query_row(
            "SELECT execution_claim_consumer FROM workloads WHERE session_id=?1",
            [session_id],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(ControllerError::SessionNotFound)
    }

    fn mutation_count(&self, session_id: &str, column: &str) -> Result<u32> {
        let conn = self.connection()?;
        let sql = match column {
            "create_mutations" => "SELECT create_mutations FROM workloads WHERE session_id=?1",
            "delete_mutations" => "SELECT delete_mutations FROM workloads WHERE session_id=?1",
            "activation_mutations" => {
                "SELECT activation_mutations FROM workloads WHERE session_id=?1"
            }
            "execution_claim_mutations" => {
                "SELECT execution_claim_mutations FROM workloads WHERE session_id=?1"
            }
            _ => return Err(ControllerError::AdapterState("unknown mutation counter")),
        };
        conn.query_row(sql, [session_id], |row| row.get(0))
            .optional()?
            .ok_or(ControllerError::SessionNotFound)
    }

    pub fn delete_owned(&self, identity: &SessionIdentity) -> Result<()> {
        <Self as WorkspaceAdapter>::delete_owned(self, identity)
    }

    pub fn workload_state(&self, session_id: &str) -> Result<ProviderWorkloadState> {
        let conn = self.connection()?;
        let state: Option<String> = conn
            .query_row(
                "SELECT launch_state FROM workloads WHERE session_id=?1",
                [session_id],
                |row| row.get(0),
            )
            .optional()?;
        match state.as_deref() {
            None => Ok(ProviderWorkloadState::Absent),
            Some("inert") => Ok(ProviderWorkloadState::Inert),
            Some("activated") => Ok(ProviderWorkloadState::Activated),
            Some("deleted") => Ok(ProviderWorkloadState::Deleted),
            Some(_) => Err(ControllerError::AdapterState(
                "invalid provider launch state",
            )),
        }
    }

    pub fn lose_next_activation_response_for_test(&self, session_id: &str) -> Result<()> {
        let conn = self.connection()?;
        let changed = conn.execute(
            "UPDATE workloads SET lose_activation_response=1 WHERE session_id=?1 AND launch_state='inert'",
            [session_id],
        )?;
        if changed != 1 {
            return Err(ControllerError::SessionNotFound);
        }
        Ok(())
    }

    pub fn replace_uid_for_test(
        &self,
        session_id: &str,
        provider_uid: &str,
        provider_generation: i64,
    ) -> Result<()> {
        let conn = self.connection()?;
        let changed = conn.execute(
            "UPDATE workloads SET provider_uid=?2,provider_generation=?3 WHERE session_id=?1 AND present=1",
            params![session_id, provider_uid, provider_generation],
        )?;
        if changed != 1 {
            return Err(ControllerError::SessionNotFound);
        }
        Ok(())
    }
}

impl WorkspaceAdapter for FakeKubernetes {
    fn create_owned(&self, identity: &SessionIdentity) -> Result<ProviderBinding> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<FakeProviderRecord> = tx
            .query_row(
                "SELECT workspace_id,capability_digest,provider_scope,create_operation_key,
                        delete_operation_key,provider_uid,provider_generation,present,
                        launch_state,activation_epoch,activation_token,activation_task_digest,
                        activation_spec_digest,lose_activation_response
                 FROM workloads WHERE session_id=?1",
                [&identity.session_id],
                FakeProviderRecord::from_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if !existing.ownership_matches(identity)
                || (!identity.provider_uid.is_empty()
                    && (existing.provider_uid != identity.provider_uid
                        || existing.provider_generation != identity.provider_generation))
            {
                return Err(ControllerError::OwnershipMismatch);
            }
            if existing.present == 1 {
                let binding = ProviderBinding {
                    provider_uid: existing.provider_uid,
                    provider_generation: existing.provider_generation,
                };
                tx.commit()?;
                return Ok(binding);
            }
            return Err(ControllerError::AdapterState(
                "cleaned workload cannot be recreated under the same session",
            ));
        }
        if tx
            .query_row(
                "SELECT 1 FROM workloads WHERE workspace_id=?1",
                [&identity.workspace_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(ControllerError::OwnershipMismatch);
        }
        if !identity.provider_uid.is_empty() || identity.provider_generation != 0 {
            return Err(ControllerError::AdapterState(
                "bound provider workload is authoritatively absent",
            ));
        }
        let binding = ProviderBinding {
            provider_uid: uuid::Uuid::new_v4().to_string(),
            provider_generation: 1,
        };
        tx.execute(
            "INSERT INTO workloads(
                session_id,workspace_id,capability_digest,provider_scope,create_operation_key,
                delete_operation_key,provider_uid,provider_generation,present,launch_state,create_mutations
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,'inert',1)",
            params![
                identity.session_id,
                identity.workspace_id,
                identity.capability_digest,
                identity.provider_scope,
                identity.create_operation_key,
                identity.delete_operation_key,
                binding.provider_uid,
                binding.provider_generation,
            ],
        )?;
        tx.commit()?;
        Ok(binding)
    }

    fn activate_owned(
        &self,
        identity: &SessionIdentity,
        capability: &ActivationCapability,
    ) -> Result<()> {
        if !capability.binding_matches(identity) {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: FakeProviderRecord = tx
            .query_row(
                "SELECT workspace_id,capability_digest,provider_scope,create_operation_key,
                        delete_operation_key,provider_uid,provider_generation,present,
                        launch_state,activation_epoch,activation_token,activation_task_digest,
                        activation_spec_digest,lose_activation_response
                 FROM workloads WHERE session_id=?1",
                [&identity.session_id],
                FakeProviderRecord::from_row,
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if !existing.matches(identity) {
            return Err(ControllerError::OwnershipMismatch);
        }
        match existing.launch_state.as_str() {
            "deleted" => Err(ControllerError::AdapterState(
                "deleted workload cannot be activated",
            )),
            "activated"
                if existing.activation_epoch == capability.launch_epoch
                    && existing.activation_token.as_deref() == Some(capability.token.as_str())
                    && existing.activation_task_digest.as_deref()
                        == Some(capability.task_input_digest.as_str())
                    && existing.activation_spec_digest.as_deref()
                        == Some(capability.execution_spec_digest.as_str()) =>
            {
                tx.commit()?;
                Ok(())
            }
            "activated" => Err(ControllerError::ActivationBindingMismatch),
            "inert" => {
                tx.execute(
                    "UPDATE workloads
                     SET launch_state='activated',activation_epoch=?2,activation_token=?3,
                         activation_task_digest=?4,activation_spec_digest=?5,
                         activation_mutations=activation_mutations+1,
                         lose_activation_response=0,updated_at=unixepoch()
                     WHERE session_id=?1 AND provider_uid=?6 AND provider_generation=?7
                           AND launch_state='inert'",
                    params![
                        identity.session_id,
                        capability.launch_epoch,
                        capability.token,
                        capability.task_input_digest,
                        capability.execution_spec_digest,
                        capability.provider_uid,
                        capability.provider_generation,
                    ],
                )?;
                let lose_response = existing.lose_activation_response == 1;
                tx.commit()?;
                if lose_response {
                    Err(ControllerError::AdapterState(
                        "provider activation response lost after commit",
                    ))
                } else {
                    Ok(())
                }
            }
            _ => Err(ControllerError::AdapterState(
                "invalid provider launch state",
            )),
        }
    }

    fn claim_execution_owned(
        &self,
        identity: &SessionIdentity,
        capability: &ActivationCapability,
        consumer_boot_id: &str,
    ) -> Result<ProviderExecutionClaim> {
        if consumer_boot_id.is_empty() || consumer_boot_id.contains('\0') {
            return Err(ControllerError::InvalidRequest(
                "consumer boot identity must be non-empty",
            ));
        }
        if !capability.binding_matches(identity) {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: FakeProviderRecord = tx
            .query_row(
                "SELECT workspace_id,capability_digest,provider_scope,create_operation_key,
                        delete_operation_key,provider_uid,provider_generation,present,
                        launch_state,activation_epoch,activation_token,activation_task_digest,
                        activation_spec_digest,lose_activation_response
                 FROM workloads WHERE session_id=?1",
                [&identity.session_id],
                FakeProviderRecord::from_row,
            )
            .optional()?
            .ok_or(ControllerError::SessionNotFound)?;
        if !existing.matches(identity) {
            return Err(ControllerError::OwnershipMismatch);
        }
        if existing.present != 1
            || existing.launch_state != "activated"
            || existing.activation_epoch != capability.launch_epoch
            || existing.activation_token.as_deref() != Some(capability.token.as_str())
            || existing.activation_task_digest.as_deref()
                != Some(capability.task_input_digest.as_str())
            || existing.activation_spec_digest.as_deref()
                != Some(capability.execution_spec_digest.as_str())
        {
            return Err(ControllerError::ActivationNotObserved);
        }
        let prior: (Option<String>, Option<String>, Option<String>) = tx.query_row(
            "SELECT execution_claim_token,execution_claim_consumer,execution_claim_spec_digest
             FROM workloads WHERE session_id=?1",
            [&identity.session_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if let Some(token) = prior.0 {
            if prior.1.as_deref() == Some(consumer_boot_id)
                && prior.2.as_deref() == Some(capability.execution_spec_digest.as_str())
            {
                tx.commit()?;
                return Ok(ProviderExecutionClaim {
                    token,
                    consumer_boot_id: consumer_boot_id.to_owned(),
                    execution_spec_digest: capability.execution_spec_digest.clone(),
                });
            }
            return Err(ControllerError::ActivationReplay);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"buzz-fake-provider-execution-claim-v1\0");
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        hasher.update(capability.token.as_bytes());
        hasher.update(consumer_boot_id.as_bytes());
        hasher.update(capability.execution_spec_digest.as_bytes());
        let token = hex::encode(hasher.finalize());
        let updated = tx.execute(
            "UPDATE workloads
             SET execution_claim_token=?2,execution_claim_consumer=?3,
                 execution_claim_spec_digest=?4,
                 execution_claim_mutations=execution_claim_mutations+1,
                 updated_at=unixepoch()
             WHERE session_id=?1 AND provider_uid=?5 AND provider_generation=?6
               AND launch_state='activated' AND activation_epoch=?7
               AND activation_token=?8 AND execution_claim_token IS NULL",
            params![
                identity.session_id,
                token,
                consumer_boot_id,
                capability.execution_spec_digest,
                identity.provider_uid,
                identity.provider_generation,
                capability.launch_epoch,
                capability.token,
            ],
        )?;
        if updated != 1 {
            return Err(ControllerError::ExecutionReplay);
        }
        tx.commit()?;
        Ok(ProviderExecutionClaim {
            token,
            consumer_boot_id: consumer_boot_id.to_owned(),
            execution_spec_digest: capability.execution_spec_digest.clone(),
        })
    }

    fn delete_owned(&self, identity: &SessionIdentity) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<FakeProviderRecord> = tx
            .query_row(
                "SELECT workspace_id,capability_digest,provider_scope,create_operation_key,
                        delete_operation_key,provider_uid,provider_generation,present,
                        launch_state,activation_epoch,activation_token,activation_task_digest,
                        activation_spec_digest,lose_activation_response
                 FROM workloads WHERE session_id=?1",
                [&identity.session_id],
                FakeProviderRecord::from_row,
            )
            .optional()?;
        let Some(existing) = existing else {
            let conflicting_session: Option<String> = tx
                .query_row(
                    "SELECT session_id FROM workloads WHERE workspace_id=?1",
                    [&identity.workspace_id],
                    |row| row.get(0),
                )
                .optional()?;
            if conflicting_session.is_some() {
                return Err(ControllerError::OwnershipMismatch);
            }
            tx.commit()?;
            return Ok(());
        };
        if !existing.matches(identity) {
            return Err(ControllerError::OwnershipMismatch);
        }
        if existing.present == 1 {
            tx.execute(
                "UPDATE workloads SET present=0,launch_state='deleted',delete_mutations=delete_mutations+1,updated_at=unixepoch() WHERE session_id=?1",
                [&identity.session_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn observe_owned(&self, identity: &SessionIdentity) -> Result<ProviderObservation> {
        let conn = self.connection()?;
        let existing: Option<FakeProviderRecord> = conn
            .query_row(
                "SELECT workspace_id,capability_digest,provider_scope,create_operation_key,
                        delete_operation_key,provider_uid,provider_generation,present,
                        launch_state,activation_epoch,activation_token,activation_task_digest,
                        activation_spec_digest,lose_activation_response
                 FROM workloads WHERE session_id=?1",
                [&identity.session_id],
                FakeProviderRecord::from_row,
            )
            .optional()?;
        let Some(existing) = existing else {
            return Ok(ProviderObservation {
                state: ProviderWorkloadState::Absent,
                provider_uid: identity.provider_uid.clone(),
                provider_generation: identity.provider_generation,
                launch_epoch: 0,
                task_input_digest: None,
            });
        };
        if !existing.matches(identity) {
            return Err(ControllerError::OwnershipMismatch);
        }
        let state = match existing.launch_state.as_str() {
            "inert" => ProviderWorkloadState::Inert,
            "activated" => ProviderWorkloadState::Activated,
            "deleted" => ProviderWorkloadState::Deleted,
            _ => {
                return Err(ControllerError::AdapterState(
                    "invalid provider launch state",
                ))
            }
        };
        Ok(ProviderObservation {
            state,
            provider_uid: existing.provider_uid,
            provider_generation: existing.provider_generation,
            launch_epoch: existing.activation_epoch,
            task_input_digest: existing.activation_task_digest,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Controller<A: WorkspaceAdapter> {
    ledger: Ledger,
    adapter: A,
}

impl<A: WorkspaceAdapter> Controller<A> {
    pub fn new(ledger: Ledger, adapter: A) -> Self {
        Self { ledger, adapter }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    fn execution_aborted(&self, session_id: &str) -> Result<bool> {
        let state = self.ledger.state(session_id)?;
        Ok(self.ledger.cancellation_requested(session_id)?
            || matches!(state, Lifecycle::Cancelled | Lifecycle::Expired))
    }

    pub fn cancel_session(&self, session_id: &str, reason: &str) -> Result<()> {
        self.ledger.request_cancellation(session_id, reason)?;
        self.reconcile_session(session_id)
    }

    pub fn expire_session(&self, session_id: &str) -> Result<()> {
        self.ledger.mark_expired(session_id)?;
        self.reconcile_session(session_id)
    }

    /// Admits a session and creates only an inert provider workload.
    pub fn provision_inert(
        &self,
        request: &AdmissionRequest,
        crash: Option<CrashPoint>,
    ) -> Result<()> {
        if crash == Some(CrashPoint::AfterPrepared) {
            self.ledger.prepare(request)?;
            crash_if(crash, CrashPoint::AfterPrepared)?;
        } else {
            self.ledger.prepare_and_admit(request)?;
        }
        if self.ledger.state(&request.session_id)? == Lifecycle::Prepared {
            self.ledger.admit(&request.session_id)?;
        }
        crash_if(crash, CrashPoint::AfterAdmitted)?;
        if self.ledger.state(&request.session_id)? == Lifecycle::Admitted {
            self.ledger.transition(
                &request.session_id,
                Lifecycle::Creating,
                "provider-create-intent",
            )?;
        }
        crash_if(crash, CrashPoint::AfterCreating)?;
        if self.execution_aborted(&request.session_id)? {
            self.reconcile_session(&request.session_id)?;
            return Err(ControllerError::ExecutionAborted);
        }
        match self.ledger.state(&request.session_id)? {
            Lifecycle::Creating => {}
            Lifecycle::Active => return Ok(()),
            Lifecycle::Rejected => return Err(ControllerError::AdmissionRejected),
            Lifecycle::Terminal | Lifecycle::Cleaning | Lifecycle::Cleaned => {
                return Err(ControllerError::ExecutionAborted);
            }
            state => {
                return Err(ControllerError::InvalidTransition {
                    from: state,
                    to: Lifecycle::Creating,
                });
            }
        }
        let identity = self.ledger.identity(&request.session_id)?;
        let binding = self.adapter.create_owned(&identity)?;
        self.ledger
            .bind_provider_identity(&request.session_id, &binding)?;
        crash_if(crash, CrashPoint::AfterProviderCreate)?;
        if self.execution_aborted(&request.session_id)? {
            self.reconcile_session(&request.session_id)?;
            return Err(ControllerError::ExecutionAborted);
        }
        Ok(())
    }

    /// Serializes authorization against cancellation and issues one bound capability.
    pub fn authorize_launch(
        &self,
        session_id: &str,
        execution_spec: &ExecutionSpec,
        expires_at: i64,
        now: i64,
    ) -> Result<ActivationCapability> {
        let identity = self.ledger.identity(session_id)?;
        self.ledger
            .authorize_launch(session_id, &identity, execution_spec, expires_at, now)
    }

    /// Projects a valid capability to the exact provider workload.
    ///
    /// Provider activation alone never grants task material or command execution.
    pub fn activate_launch(&self, capability: &ActivationCapability) -> Result<()> {
        if self.execution_aborted(&capability.session_id)? {
            self.reconcile_session(&capability.session_id)?;
            return Err(ControllerError::ExecutionAborted);
        }
        self.ledger.validate_launch(capability)?;
        let identity = self.ledger.identity(&capability.session_id)?;
        self.adapter.activate_owned(&identity, capability)
    }

    /// Consumes a capability at the task-material/execution linearization point.
    pub fn redeem_launch(
        &self,
        capability: &ActivationCapability,
        consumer_boot_id: &str,
        execution_spec: &ExecutionSpec,
        now: i64,
    ) -> Result<TaskMaterialGrant> {
        if self.execution_aborted(&capability.session_id)? {
            return Err(ControllerError::ExecutionAborted);
        }
        let identity = self.ledger.identity(&capability.session_id)?;
        let observed = self.adapter.observe_owned(&identity)?;
        if observed.state != ProviderWorkloadState::Activated
            || observed.provider_uid != capability.provider_uid
            || observed.provider_generation != capability.provider_generation
            || observed.launch_epoch != capability.launch_epoch
            || observed.task_input_digest.as_deref() != Some(capability.task_input_digest.as_str())
        {
            return Err(ControllerError::ActivationNotObserved);
        }
        let provider_claim =
            self.adapter
                .claim_execution_owned(&identity, capability, consumer_boot_id)?;
        if provider_claim.consumer_boot_id != consumer_boot_id
            || provider_claim.execution_spec_digest != capability.execution_spec_digest
        {
            return Err(ControllerError::ActivationBindingMismatch);
        }
        self.ledger.redeem_launch(
            capability,
            consumer_boot_id,
            &provider_claim.token,
            execution_spec,
            now,
        )
    }

    pub fn provision(&self, request: &AdmissionRequest, crash: Option<CrashPoint>) -> Result<()> {
        self.provision_inert(request, crash)?;
        self.reconcile_session(&request.session_id)
    }

    pub fn accept_and_cleanup(
        &self,
        receipt: &TerminalReceipt,
        owner_id: &str,
        workspace_id: &str,
        crash: Option<CrashPoint>,
    ) -> Result<()> {
        let identity = self.ledger.identity(&receipt.session_id)?;
        if identity.owner_id != owner_id || identity.workspace_id != workspace_id {
            return Err(ControllerError::OwnershipMismatch);
        }
        self.ledger.record_terminal(receipt)?;
        crash_if(crash, CrashPoint::AfterTerminal)?;
        let claim = cleanup_claim(&identity);
        self.ledger.begin_cleanup(
            &identity.session_id,
            &identity.owner_id,
            &identity.workspace_id,
            &claim,
        )?;
        crash_if(crash, CrashPoint::AfterCleaning)?;
        self.adapter.delete_owned(&identity)?;
        crash_if(crash, CrashPoint::AfterProviderDelete)?;
        if self.adapter.exists_owned(&identity)? {
            return Err(ControllerError::AdapterState(
                "provider deletion is not authoritatively absent",
            ));
        }
        self.ledger.mark_cleaned(&identity.session_id, &claim)?;
        crash_if(crash, CrashPoint::AfterCleaned)?;
        Ok(())
    }

    pub fn reconcile_session(&self, session_id: &str) -> Result<()> {
        for _ in 0..8 {
            let state = self.ledger.state(session_id)?;
            let identity = self.ledger.identity(session_id)?;
            if self.ledger.cancellation_requested(session_id)?
                && matches!(
                    state,
                    Lifecycle::Prepared
                        | Lifecycle::Admitted
                        | Lifecycle::Creating
                        | Lifecycle::Active
                        | Lifecycle::RecoveryError
                )
            {
                self.ledger.transition(
                    session_id,
                    Lifecycle::Cancelled,
                    "reconcile-cancellation",
                )?;
                continue;
            }
            match state {
                Lifecycle::Prepared => {
                    self.ledger.admit(session_id)?;
                }
                Lifecycle::Admitted => {
                    self.ledger.transition(
                        session_id,
                        Lifecycle::Creating,
                        "reconcile-create-intent",
                    )?;
                }
                Lifecycle::Creating => {
                    let binding = self.adapter.create_owned(&identity)?;
                    self.ledger.bind_provider_identity(session_id, &binding)?;
                    if self.execution_aborted(session_id)? {
                        continue;
                    }
                    if self.ledger.state(session_id)? == Lifecycle::Active {
                        return Ok(());
                    }
                    let Some(capability) = self.ledger.current_issued_launch(session_id)? else {
                        return Ok(());
                    };
                    let identity = self.ledger.identity(session_id)?;
                    if let Err(error) = self.adapter.activate_owned(&identity, &capability) {
                        let observed = self.adapter.observe_owned(&identity)?;
                        let exact_activation_observed = observed.state
                            == ProviderWorkloadState::Activated
                            && observed.provider_uid == capability.provider_uid
                            && observed.provider_generation == capability.provider_generation
                            && observed.launch_epoch == capability.launch_epoch
                            && observed.task_input_digest.as_deref()
                                == Some(capability.task_input_digest.as_str());
                        if !exact_activation_observed {
                            return Err(error);
                        }
                    }
                    if self.execution_aborted(session_id)? {
                        continue;
                    }
                    return Ok(());
                }
                Lifecycle::Active | Lifecycle::Cleaned | Lifecycle::Rejected => return Ok(()),
                Lifecycle::Terminal | Lifecycle::Cancelled | Lifecycle::Expired => {
                    let claim = cleanup_claim(&identity);
                    self.ledger.begin_cleanup(
                        session_id,
                        &identity.owner_id,
                        &identity.workspace_id,
                        &claim,
                    )?;
                }
                Lifecycle::Cleaning => {
                    let claim = self
                        .ledger
                        .cleanup_claim(session_id)?
                        .ok_or(ControllerError::AdapterState("cleaning state lacks claim"))?;
                    self.adapter.delete_owned(&identity)?;
                    if self.adapter.exists_owned(&identity)? {
                        return Err(ControllerError::AdapterState(
                            "provider deletion is not authoritatively absent",
                        ));
                    }
                    self.ledger.mark_cleaned(session_id, &claim)?;
                }
                Lifecycle::RecoveryError => {
                    if self.ledger.cancellation_requested(session_id)?
                        || matches!(
                            self.ledger.state(session_id)?,
                            Lifecycle::Cancelled | Lifecycle::Expired | Lifecycle::Terminal
                        )
                    {
                        let claim = cleanup_claim(&identity);
                        self.ledger.begin_cleanup(
                            session_id,
                            &identity.owner_id,
                            &identity.workspace_id,
                            &claim,
                        )?;
                    } else if self.ledger.cleanup_claim(session_id)?.is_some() {
                        self.ledger.transition(
                            session_id,
                            Lifecycle::Cleaning,
                            "reconcile-cleanup-error",
                        )?;
                    } else if self.adapter.exists_owned(&identity)? {
                        self.ledger.transition(
                            session_id,
                            Lifecycle::Creating,
                            "reconcile-found-inert-or-activated-provider",
                        )?;
                    } else {
                        self.ledger.transition(
                            session_id,
                            Lifecycle::Creating,
                            "reconcile-retry-provider",
                        )?;
                    }
                }
            }
        }
        Err(ControllerError::AdapterState(
            "reconciliation exceeded transition bound",
        ))
    }
}

fn cleanup_claim(identity: &SessionIdentity) -> String {
    format!("cleanup:{}:{}", identity.session_id, identity.workspace_id)
}

fn crash_if(actual: Option<CrashPoint>, expected: CrashPoint) -> Result<()> {
    if actual == Some(expected) {
        Err(ControllerError::SimulatedCrash(expected))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerExit {
    CancelledBeforeSpawn,
    Cancelled,
    Exited(Option<i32>),
}

/// Runs a local worker only after validating an exact redeemed task-material grant.
///
/// Authoritative cancellation is checked before spawn and continuously polled;
/// loss of ledger authority terminates the process tree and fails closed.
pub fn run_cancellable_process(
    ledger: &Ledger,
    grant: &TaskMaterialGrant,
    poll_interval: Duration,
) -> Result<WorkerExit> {
    let mut child = ledger.claim_and_spawn_task_material_grant(grant, || {})?;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(WorkerExit::Exited(status.code()));
        }
        match ledger.cancellation_requested(&grant.session_id) {
            Ok(true) => {
                terminate_process_tree(&mut child)?;
                return Ok(WorkerExit::Cancelled);
            }
            Ok(false) => {}
            Err(error) => {
                terminate_process_tree(&mut child)?;
                return Err(error);
            }
        }
        std::thread::sleep(poll_interval);
    }
}

#[cfg(windows)]
fn configure_process_group(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP);
}

#[cfg(unix)]
fn configure_process_group(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(any(windows, unix)))]
fn configure_process_group(_command: &mut std::process::Command) {}

#[cfg(windows)]
fn terminate_process_tree(child: &mut std::process::Child) -> Result<()> {
    use std::process::Stdio;
    let status = std::process::Command::new("taskkill.exe")
        .args(["/PID", &child.id().to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    let child_status = child.wait()?;
    if !status.success() && child_status.success() {
        return Err(ControllerError::AdapterState(
            "process-tree termination command failed",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn terminate_process_tree(child: &mut std::process::Child) -> Result<()> {
    use std::process::Stdio;

    let process_group = format!("-{}", child.id());
    let term = std::process::Command::new("kill")
        .args(["-TERM", "--", &process_group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !term.success() && child.try_wait()?.is_none() {
        return Err(ControllerError::AdapterState(
            "process-group termination command failed",
        ));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let kill = std::process::Command::new("kill")
        .args(["-KILL", "--", &process_group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !kill.success() && child.try_wait()?.is_none() {
        return Err(ControllerError::AdapterState(
            "process-group kill command failed",
        ));
    }
    child.wait()?;
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn terminate_process_tree(child: &mut std::process::Child) -> Result<()> {
    child.kill()?;
    child.wait()?;
    Ok(())
}

#[cfg(test)]
mod spawn_linearization_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn cancellation_cannot_commit_between_execution_claim_and_physical_spawn() {
        const NOW: i64 = 1_900_000_000;
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("ledger.db");
        let provider_path = dir.path().join("provider.db");
        let controller = Controller::new(
            Ledger::open(&ledger_path).unwrap(),
            FakeKubernetes::open(&provider_path).unwrap(),
        );
        let task_digest = "a".repeat(64);
        let request = AdmissionRequest {
            session_id: "spawn-race-session".into(),
            jti: "spawn-race-jti".into(),
            capability_digest: "sha256:spawn-race-capability".into(),
            owner_id: "agent:spawn-race".into(),
            workspace_id: "spawn-race-workspace".into(),
            scope: Scope::Agent("agent:spawn-race".into()),
            signed_max_concurrency: 1,
            deployment_max_concurrency: 1,
            artifact_limit_bytes: 1,
            expires_at: 2_000_000_000,
        };
        controller.provision_inert(&request, None).unwrap();
        let spec = ExecutionSpec::new(
            std::env::current_exe().unwrap().to_string_lossy(),
            vec!["--help".into()],
            &task_digest,
        )
        .unwrap();
        let capability = controller
            .authorize_launch(&request.session_id, &spec, NOW + 60, NOW)
            .unwrap();
        controller.activate_launch(&capability).unwrap();
        let grant = controller
            .redeem_launch(&capability, "spawn-race-boot", &spec, NOW)
            .unwrap();
        drop(controller);

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_ledger = Ledger::open(&ledger_path).unwrap();
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let worker = thread::spawn(move || {
            let mut child = worker_ledger.claim_and_spawn_task_material_grant(&grant, || {
                worker_entered.wait();
                worker_release.wait();
            })?;
            child.wait()?;
            Result::<()>::Ok(())
        });

        entered.wait();
        let cancellation_path = ledger_path.clone();
        let cancellation = thread::spawn(move || {
            Ledger::open(cancellation_path)
                .unwrap()
                .request_cancellation("spawn-race-session", "race-test")
        });
        thread::sleep(Duration::from_millis(100));
        assert!(
            !cancellation.is_finished(),
            "cancellation committed while execution claim held the writer transaction"
        );

        release.wait();
        worker.join().unwrap().unwrap();
        cancellation.join().unwrap().unwrap();
        assert_eq!(
            Ledger::open(&ledger_path)
                .unwrap()
                .state("spawn-race-session")
                .unwrap(),
            Lifecycle::Cancelled
        );
    }
}
