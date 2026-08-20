use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use chrono::{DateTime, Utc};

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Secret not found: {0}")]
    NotFound(String),

    #[error("Provider error ({provider}): {message}")]
    ProviderError {
        provider: String,
        message: String,
    },

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
    async fn set_secret(&self, key: &str, value: &str, description: Option<&str>) -> Result<(), SecretError>;

    /// Delete a secret by key.
    async fn delete_secret(&self, key: &str) -> Result<(), SecretError>;

    /// List available secret metadata.
    async fn list_secrets(&self) -> Result<Vec<SecretMetadata>, SecretError>;
}

/// Attribute-Based Access Control (ABAC) Policy for an agent invoking tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPolicy {
    /// Agent pubkey (hex or npub prefix).
    pub agent_pubkey: String,
    /// Secret keys this agent is permitted to lease.
    pub allowed_secrets: Vec<String>,
    /// Specific tools permitted to consume the secret (e.g. ["web_search", "github"]).
    pub allowed_tools: Vec<String>,
    /// Maximum lease duration in seconds (default 300 = 5 minutes).
    pub max_lease_ttl_secs: u64,
}

/// A time-bounded, tool-scoped secret lease for an agent execution turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Memory-backed secret provider for unit testing and ephemeral sandboxes.
pub struct InMemorySecretVault {
    secrets: tokio::sync::RwLock<HashMap<String, (String, Option<String>, DateTime<Utc>)>>,
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

    async fn set_secret(&self, key: &str, value: &str, description: Option<&str>) -> Result<(), SecretError> {
        let mut lock = self.secrets.write().await;
        lock.insert(
            key.to_string(),
            (value.to_string(), description.map(str::to_string), Utc::now()),
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
    policies: tokio::sync::RwLock<HashMap<String, SecretPolicy>>,
}

impl SecretBroker {
    pub fn new(providers: Vec<Arc<dyn SecretVaultProvider>>) -> Self {
        Self {
            providers,
            policies: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    pub async fn add_policy(&self, policy: SecretPolicy) {
        let mut lock = self.policies.write().await;
        lock.insert(policy.agent_pubkey.clone(), policy);
    }

    /// Resolve a secret across registered providers in priority order.
    pub async fn resolve_secret(&self, key: &str) -> Result<String, SecretError> {
        for provider in &self.providers {
            if let Ok(val) = provider.get_secret(key).await {
                return Ok(val);
            }
        }
        Err(SecretError::NotFound(key.to_string()))
    }

    /// Issue an ABAC-gated lease for an agent turn.
    pub async fn acquire_lease(
        &self,
        agent_pubkey: &str,
        tool: &str,
        secret_key: &str,
    ) -> Result<SecretLease, SecretError> {
        let lock = self.policies.read().await;
        let policy = lock.get(agent_pubkey).ok_or_else(|| SecretError::AccessDenied {
            agent_pubkey: agent_pubkey.to_string(),
            secret_key: secret_key.to_string(),
            tool: tool.to_string(),
        })?;

        // Check if secret key and tool are authorized
        let secret_allowed = policy.allowed_secrets.iter().any(|s| s == "*" || s == secret_key);
        let tool_allowed = policy.allowed_tools.iter().any(|t| t == "*" || t == tool);

        if !secret_allowed || !tool_allowed {
            return Err(SecretError::AccessDenied {
                agent_pubkey: agent_pubkey.to_string(),
                secret_key: secret_key.to_string(),
                tool: tool.to_string(),
            });
        }

        let secret_value = self.resolve_secret(secret_key).await?;
        let ttl_secs = if policy.max_lease_ttl_secs > 0 { policy.max_lease_ttl_secs } else { 300 };
        let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs as i64);

        Ok(SecretLease {
            lease_id: format!("lease_{}_{}", agent_pubkey, secret_key),
            secret_key: secret_key.to_string(),
            value: secret_value,
            agent_pubkey: agent_pubkey.to_string(),
            tool: tool.to_string(),
            expires_at,
        })
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
                let entry = keyring::Entry::new(&service, &key_str)
                    .map_err(|e| SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: e.to_string(),
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

        async fn set_secret(&self, key: &str, value: &str, _description: Option<&str>) -> Result<(), SecretError> {
            let service = self.service_name.clone();
            let key_str = key.to_string();
            let val_str = value.to_string();
            tokio::task::spawn_blocking(move || {
                let entry = keyring::Entry::new(&service, &key_str)
                    .map_err(|e| SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: e.to_string(),
                    })?;
                entry.set_password(&val_str).map_err(|e| SecretError::ProviderError {
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
                let entry = keyring::Entry::new(&service, &key_str)
                    .map_err(|e| SecretError::ProviderError {
                        provider: "os-keyring".to_string(),
                        message: e.to_string(),
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

    /// Bitwarden Secrets Manager (BWS) CLI wrapper provider.
    pub struct BwsVault {
        access_token: Option<String>,
    }

    impl BwsVault {
        pub fn new(access_token: Option<String>) -> Self {
            Self { access_token }
        }

        fn get_token(&self) -> Result<String, SecretError> {
            if let Some(t) = &self.access_token {
                return Ok(t.clone());
            }
            std::env::var("BWS_ACCESS_TOKEN").map_err(|_| SecretError::InvalidConfig("BWS_ACCESS_TOKEN is not configured in provider or environment".to_string()))
        }
    }

    #[async_trait]
    impl SecretVaultProvider for BwsVault {
        fn name(&self) -> &str {
            "bws"
        }

        async fn get_secret(&self, key: &str) -> Result<String, SecretError> {
            let token = self.get_token()?;
            let output = tokio::process::Command::new("bws")
                .args(["secret", "get", key, "--access-token", &token, "--output", "json"])
                .output()
                .await
                .map_err(SecretError::Io)?;

            if !output.status.success() {
                let err_str = String::from_utf8_lossy(&output.stderr);
                return Err(SecretError::ProviderError {
                    provider: "bws".to_string(),
                    message: err_str.to_string(),
                });
            }

            let json: serde_json::Value = serde_json::from_slice(&output.stdout)
                .map_err(|e| SecretError::ProviderError {
                    provider: "bws".to_string(),
                    message: format!("JSON parse error: {}", e),
                })?;

            if let Some(val) = json.get("value").and_then(|v| v.as_str()) {
                Ok(val.to_string())
            } else {
                Err(SecretError::NotFound(key.to_string()))
            }
        }

        async fn set_secret(&self, _key: &str, _value: &str, _description: Option<&str>) -> Result<(), SecretError> {
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
            let token = self.get_token()?;
            let output = tokio::process::Command::new("bws")
                .args(["secret", "list", "--access-token", &token, "--output", "json"])
                .output()
                .await
                .map_err(SecretError::Io)?;

            if !output.status.success() {
                return Ok(vec![]);
            }

            let items: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout).unwrap_or_default();
            let mut list = Vec::new();
            for item in items {
                if let Some(key) = item.get("key").and_then(|k| k.as_str()) {
                    list.push(SecretMetadata {
                        key: key.to_string(),
                        description: item.get("note").and_then(|n| n.as_str()).map(str::to_string),
                        provider: "bws".to_string(),
                        updated_at: Utc::now(),
                    });
                }
            }
            Ok(list)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_vault_crud() {
        let vault = InMemorySecretVault::new();
        vault.set_secret("OPENROUTER_API_KEY", "sk-or-test-12345", Some("Test key")).await.unwrap();

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
        vault.set_secret("OPENROUTER_API_KEY", "sk-or-secret-val", None).await.unwrap();
        vault.set_secret("DATABASE_PASSWORD", "super-secret-db", None).await.unwrap();

        let broker = SecretBroker::new(vec![vault]);

        // Define policy for agent1: only permitted to access OPENROUTER_API_KEY on tool "model_inference"
        broker.add_policy(SecretPolicy {
            agent_pubkey: "agent1".to_string(),
            allowed_secrets: vec!["OPENROUTER_API_KEY".to_string()],
            allowed_tools: vec!["model_inference".to_string()],
            max_lease_ttl_secs: 60,
        }).await;

        // Authorized lease
        let lease = broker.acquire_lease("agent1", "model_inference", "OPENROUTER_API_KEY").await.unwrap();
        assert_eq!(lease.value, "sk-or-secret-val");
        assert!(lease.is_valid());

        // Unauthorized tool
        let tool_denied = broker.acquire_lease("agent1", "terminal", "OPENROUTER_API_KEY").await;
        assert!(tool_denied.is_err());

        // Unauthorized secret
        let secret_denied = broker.acquire_lease("agent1", "model_inference", "DATABASE_PASSWORD").await;
        assert!(secret_denied.is_err());

        // Unauthorized agent
        let agent_denied = broker.acquire_lease("agent_unknown", "model_inference", "OPENROUTER_API_KEY").await;
        assert!(agent_denied.is_err());
    }
}
