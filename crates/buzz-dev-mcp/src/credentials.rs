use std::ffi::{OsStr, OsString};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use zeroize::Zeroizing;

pub(crate) const CREDENTIAL_MODE_ENV: &str = "BUZZ_CREDENTIAL_MODE";
pub(crate) const CAPABILITY_ENDPOINT_ENV: &str = "BUZZ_CAPABILITY_ENDPOINT";
pub(crate) const CAPABILITY_ID_ENV: &str = "BUZZ_CAPABILITY_ID";
pub(crate) const CAPABILITY_TOKEN_ENV: &str = "BUZZ_CAPABILITY_TOKEN";
pub(crate) const PUBLIC_KEY_ENV: &str = "BUZZ_PUBLIC_KEY";
pub(crate) const RELAY_URL_ENV: &str = "BUZZ_RELAY_URL";
pub(crate) const CAPABILITY_EXPIRES_AT_ENV: &str = "BUZZ_CAPABILITY_EXPIRES_AT";

const CAPABILITY_ENV_PREFIX: &str = "BUZZ_CAPABILITY_";
const PROJECTION_ENV: [&str; 6] = [
    CAPABILITY_ENDPOINT_ENV,
    CAPABILITY_ID_ENV,
    CAPABILITY_TOKEN_ENV,
    PUBLIC_KEY_ENV,
    RELAY_URL_ENV,
    CAPABILITY_EXPIRES_AT_ENV,
];
pub(crate) const LONG_LIVED_CREDENTIAL_ENV: [&str; 4] = [
    "BUZZ_PRIVATE_KEY",
    "BUZZ_ACP_PRIVATE_KEY",
    "NOSTR_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
];

/// Secret-safe credential configuration failures for this consumer boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialError {
    InvalidMode,
    MissingProjection,
    IncompleteProjection,
    MixedCredentials,
    UnsupportedEnvironment,
    InvalidEnvironment,
    InvalidEndpoint,
    InvalidCapabilityId,
    InvalidToken,
    InvalidPublicKey,
    InvalidRelay,
    InvalidExpiry,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMode => "credential mode must be legacy-env or broker-v1",
            Self::MissingProjection => "capability projection is missing",
            Self::IncompleteProjection => "capability projection is incomplete",
            Self::MixedCredentials => {
                "long-lived credentials cannot be mixed with a capability projection"
            }
            Self::UnsupportedEnvironment => {
                "capability projection contains an unsupported variable"
            }
            Self::InvalidEnvironment => "capability projection contains invalid environment text",
            Self::InvalidEndpoint => "capability endpoint must be tcp://127.0.0.1:<nonzero-port>",
            Self::InvalidCapabilityId => "capability identifier is invalid",
            Self::InvalidToken => "capability token is invalid",
            Self::InvalidPublicKey => "capability public key is invalid",
            Self::InvalidRelay => "capability relay is invalid",
            Self::InvalidExpiry => "capability expiry is invalid",
        })
    }
}

impl std::error::Error for CredentialError {}

pub(crate) enum ChildCredentials {
    LegacyEnv,
    BrokerV1(BrokerProjection),
}

impl ChildCredentials {
    pub(crate) fn from_env() -> Result<Self, CredentialError> {
        let mode = std::env::var_os(CREDENTIAL_MODE_ENV);
        Self::parse(mode.as_deref(), std::env::vars_os())
    }

    fn parse<I>(mode: Option<&OsStr>, variables: I) -> Result<Self, CredentialError>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        match mode {
            None => Ok(Self::LegacyEnv),
            Some(value) if value.to_str() == Some("legacy-env") => Ok(Self::LegacyEnv),
            Some(value) if value.to_str() == Some("broker-v1") => {
                BrokerProjection::parse(variables).map(Self::BrokerV1)
            }
            Some(value) if value.to_str().is_none() => Err(CredentialError::InvalidEnvironment),
            Some(_) => Err(CredentialError::InvalidMode),
        }
    }

    pub(crate) fn is_broker_v1(&self) -> bool {
        matches!(self, Self::BrokerV1(_))
    }

    pub(crate) fn broker_relay(&self) -> Option<&reqwest::Url> {
        match self {
            Self::LegacyEnv => None,
            Self::BrokerV1(projection) => Some(&projection.relay_url),
        }
    }

    #[cfg(test)]
    pub(crate) fn broker_for_tests(relay: &str) -> Self {
        let variables = vec![
            (
                OsString::from(CAPABILITY_ENDPOINT_ENV),
                OsString::from("tcp://127.0.0.1:32123"),
            ),
            (
                OsString::from(CAPABILITY_ID_ENV),
                OsString::from("d2719d29-ff5d-4d85-b332-7030bf222e5d"),
            ),
            (
                OsString::from(CAPABILITY_TOKEN_ENV),
                OsString::from("t".repeat(32)),
            ),
            (
                OsString::from(PUBLIC_KEY_ENV),
                OsString::from("dcfd242e557282d7a1e2cf2e6877522682f1e5c6156dc92ca7d90eaedd3b0f95"),
            ),
            (OsString::from(RELAY_URL_ENV), OsString::from(relay)),
            (
                OsString::from(CAPABILITY_EXPIRES_AT_ENV),
                OsString::from("4102444800000"),
            ),
        ];
        match BrokerProjection::parse(variables) {
            Ok(projection) => Self::BrokerV1(projection),
            Err(error) => panic!("valid test projection: {error}"),
        }
    }

    /// Apply the credential boundary last, after all ordinary child setup.
    pub(crate) fn apply_to_command(&self, command: &mut tokio::process::Command) {
        let Self::BrokerV1(projection) = self else {
            return;
        };

        for name in LONG_LIVED_CREDENTIAL_ENV {
            command.env_remove(name);
        }
        let configured_reserved: Vec<OsString> = command
            .as_std()
            .get_envs()
            .filter_map(|(name, _)| {
                name.to_str()
                    .filter(|name| is_reserved_child_env(name) || is_ephemeral_git_config_env(name))
                    .map(OsString::from)
            })
            .collect();
        for name in configured_reserved {
            command.env_remove(name);
        }
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(|name| {
                is_reserved_child_env(name) || is_ephemeral_git_config_env(name)
            }) {
                command.env_remove(name);
            }
        }

        command.env(CAPABILITY_ENDPOINT_ENV, &projection.endpoint);
        command.env(CAPABILITY_ID_ENV, projection.capability_id.to_string());
        command.env(CAPABILITY_TOKEN_ENV, projection.token.as_str());
        command.env(PUBLIC_KEY_ENV, &projection.public_key);
        command.env(
            RELAY_URL_ENV,
            projection.relay_url.as_str().trim_end_matches('/'),
        );
        command.env(
            CAPABILITY_EXPIRES_AT_ENV,
            projection.expires_at_unix_ms.to_string(),
        );
    }
}

pub(crate) struct BrokerProjection {
    endpoint: String,
    capability_id: uuid::Uuid,
    token: Zeroizing<String>,
    public_key: String,
    relay_url: reqwest::Url,
    expires_at_unix_ms: i64,
}

impl BrokerProjection {
    fn parse<I>(variables: I) -> Result<Self, CredentialError>
    where
        I: IntoIterator<Item = (OsString, OsString)>,
    {
        let mut values: [Option<OsString>; 6] = std::array::from_fn(|_| None);
        let mut saw_long_lived = false;

        for (raw_name, value) in variables {
            let Some(name) = raw_name.to_str() else {
                continue;
            };
            if is_long_lived_credential_env(name) {
                saw_long_lived = true;
                continue;
            }
            if let Some(index) = PROJECTION_ENV.iter().position(|expected| name == *expected) {
                if values[index].replace(value).is_some() {
                    return Err(CredentialError::UnsupportedEnvironment);
                }
                continue;
            }
            if PROJECTION_ENV
                .iter()
                .any(|expected| name.eq_ignore_ascii_case(expected))
                || has_capability_prefix(name)
            {
                return Err(CredentialError::UnsupportedEnvironment);
            }
        }

        let present = values.iter().filter(|value| value.is_some()).count();
        if present == 0 {
            return Err(if saw_long_lived {
                CredentialError::MixedCredentials
            } else {
                CredentialError::MissingProjection
            });
        }
        if saw_long_lived {
            return Err(CredentialError::MixedCredentials);
        }
        if present != values.len() {
            return Err(CredentialError::IncompleteProjection);
        }

        let [endpoint, capability_id, token, public_key, relay_url, expires_at] = values;
        let endpoint = into_string(endpoint)?;
        let capability_id = into_string(capability_id)?;
        let token = Zeroizing::new(into_string(token)?);
        let public_key = into_string(public_key)?;
        let relay_url = into_string(relay_url)?;
        let expires_at = into_string(expires_at)?;

        let endpoint = parse_endpoint(&endpoint)?;
        let capability_id = uuid::Uuid::parse_str(&capability_id)
            .ok()
            .filter(|id| !id.is_nil())
            .ok_or(CredentialError::InvalidCapabilityId)?;
        if !(32..=256).contains(&token.len()) || token.chars().any(char::is_whitespace) {
            return Err(CredentialError::InvalidToken);
        }
        let parsed_public_key =
            nostr::PublicKey::parse(&public_key).map_err(|_| CredentialError::InvalidPublicKey)?;
        if parsed_public_key.to_hex() != public_key {
            return Err(CredentialError::InvalidPublicKey);
        }
        let relay_url = parse_relay_origin(&relay_url)?;
        let expires_at_unix_ms = expires_at
            .parse::<i64>()
            .ok()
            .filter(|expiry| *expiry > 0)
            .ok_or(CredentialError::InvalidExpiry)?;

        Ok(Self {
            endpoint,
            capability_id,
            token,
            public_key,
            relay_url,
            expires_at_unix_ms,
        })
    }
}

fn into_string(value: Option<OsString>) -> Result<String, CredentialError> {
    value
        .ok_or(CredentialError::IncompleteProjection)?
        .into_string()
        .map_err(|_| CredentialError::InvalidEnvironment)
}

fn parse_endpoint(value: &str) -> Result<String, CredentialError> {
    let endpoint = reqwest::Url::parse(value).map_err(|_| CredentialError::InvalidEndpoint)?;
    if endpoint.scheme() != "tcp"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.path().is_empty()
        || endpoint.host_str() != Some("127.0.0.1")
    {
        return Err(CredentialError::InvalidEndpoint);
    }
    let port = endpoint
        .port()
        .filter(|port| *port != 0)
        .ok_or(CredentialError::InvalidEndpoint)?;
    let canonical = format!("tcp://{}", SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    if value != canonical {
        return Err(CredentialError::InvalidEndpoint);
    }
    Ok(canonical)
}

fn parse_relay_origin(value: &str) -> Result<reqwest::Url, CredentialError> {
    let mut relay = reqwest::Url::parse(value).map_err(|_| CredentialError::InvalidRelay)?;
    if !matches!(relay.scheme(), "ws" | "wss" | "http" | "https")
        || relay.host_str().is_none()
        || !relay.username().is_empty()
        || relay.password().is_some()
        || relay.query().is_some()
        || relay.fragment().is_some()
        || !matches!(relay.path(), "" | "/")
    {
        return Err(CredentialError::InvalidRelay);
    }
    let host = relay
        .host_str()
        .ok_or(CredentialError::InvalidRelay)?
        .to_ascii_lowercase();
    relay
        .set_host(Some(&host))
        .map_err(|_| CredentialError::InvalidRelay)?;
    relay.set_path("");
    let canonical = relay.as_str().trim_end_matches('/');
    if value != canonical {
        return Err(CredentialError::InvalidRelay);
    }
    Ok(relay)
}

fn is_long_lived_credential_env(name: &str) -> bool {
    LONG_LIVED_CREDENTIAL_ENV
        .iter()
        .any(|expected| name.eq_ignore_ascii_case(expected))
}

fn has_capability_prefix(name: &str) -> bool {
    name.get(..CAPABILITY_ENV_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(CAPABILITY_ENV_PREFIX))
}

fn is_reserved_child_env(name: &str) -> bool {
    is_long_lived_credential_env(name)
        || has_capability_prefix(name)
        || PROJECTION_ENV
            .iter()
            .any(|expected| name.eq_ignore_ascii_case(expected))
}

fn is_ephemeral_git_config_env(name: &str) -> bool {
    name.eq_ignore_ascii_case("GIT_CONFIG_COUNT")
        || name
            .get(.."GIT_CONFIG_KEY_".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("GIT_CONFIG_KEY_"))
        || name
            .get(.."GIT_CONFIG_VALUE_".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("GIT_CONFIG_VALUE_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_KEY: &str = "dcfd242e557282d7a1e2cf2e6877522682f1e5c6156dc92ca7d90eaedd3b0f95";

    fn projection() -> Vec<(OsString, OsString)> {
        vec![
            (
                OsString::from(CAPABILITY_ENDPOINT_ENV),
                OsString::from("tcp://127.0.0.1:32123"),
            ),
            (
                OsString::from(CAPABILITY_ID_ENV),
                OsString::from("d2719d29-ff5d-4d85-b332-7030bf222e5d"),
            ),
            (
                OsString::from(CAPABILITY_TOKEN_ENV),
                OsString::from("t".repeat(32)),
            ),
            (OsString::from(PUBLIC_KEY_ENV), OsString::from(PUBLIC_KEY)),
            (
                OsString::from(RELAY_URL_ENV),
                OsString::from("wss://relay.example.com"),
            ),
            (
                OsString::from(CAPABILITY_EXPIRES_AT_ENV),
                OsString::from("4102444800000"),
            ),
        ]
    }

    #[test]
    fn legacy_default_and_explicit_mode_remain_available() {
        assert!(matches!(
            ChildCredentials::parse(None, Vec::<(OsString, OsString)>::new()),
            Ok(ChildCredentials::LegacyEnv)
        ));
        assert!(matches!(
            ChildCredentials::parse(
                Some(OsStr::new("legacy-env")),
                Vec::<(OsString, OsString)>::new()
            ),
            Ok(ChildCredentials::LegacyEnv)
        ));
        assert!(matches!(
            ChildCredentials::parse(Some(OsStr::new("")), Vec::<(OsString, OsString)>::new()),
            Err(CredentialError::InvalidMode)
        ));
    }

    #[test]
    fn broker_requires_exactly_one_complete_projection() {
        let mode = Some(OsStr::new("broker-v1"));
        assert!(matches!(
            ChildCredentials::parse(mode, Vec::<(OsString, OsString)>::new()),
            Err(CredentialError::MissingProjection)
        ));
        let mut partial = projection();
        partial.pop();
        assert!(matches!(
            ChildCredentials::parse(mode, partial),
            Err(CredentialError::IncompleteProjection)
        ));
        assert!(matches!(
            ChildCredentials::parse(mode, projection()),
            Ok(ChildCredentials::BrokerV1(_))
        ));
    }

    #[test]
    fn broker_rejects_mixed_credentials_without_echoing_values() {
        for alias in LONG_LIVED_CREDENTIAL_ENV {
            let canary = "PRIVATE_CANARY_DO_NOT_LOG";
            let mut variables = projection();
            variables.push((OsString::from(alias), OsString::from(canary)));
            let error = ChildCredentials::parse(Some(OsStr::new("broker-v1")), variables)
                .err()
                .expect("mixed projection must fail");
            assert_eq!(error, CredentialError::MixedCredentials);
            assert!(!error.to_string().contains(canary));
        }
    }

    #[test]
    fn broker_rejects_case_aliases_and_unknown_capability_variables() {
        let mut mixed = projection();
        mixed.push((OsString::from("nostr_private_key"), OsString::from("x")));
        assert!(matches!(
            ChildCredentials::parse(Some(OsStr::new("broker-v1")), mixed),
            Err(CredentialError::MixedCredentials)
        ));

        let mut unsupported = projection();
        unsupported.push((
            OsString::from("BUZZ_CAPABILITY_SURPRISE"),
            OsString::from("x"),
        ));
        assert!(matches!(
            ChildCredentials::parse(Some(OsStr::new("broker-v1")), unsupported),
            Err(CredentialError::UnsupportedEnvironment)
        ));
    }

    #[test]
    fn broker_errors_are_secret_safe() {
        let canary = "SUPER_SECRET_CANARY_2187";
        let mut variables = projection();
        variables.retain(|(name, _)| name != CAPABILITY_TOKEN_ENV);
        variables.push((OsString::from(CAPABILITY_TOKEN_ENV), OsString::from(canary)));
        let error = ChildCredentials::parse(Some(OsStr::new("broker-v1")), variables)
            .err()
            .expect("short token must fail");
        assert_eq!(error, CredentialError::InvalidToken);
        assert!(!format!("{error:?} {error}").contains(canary));
    }

    #[test]
    fn broker_child_environment_removes_keys_and_keeps_only_fixed_projection() {
        let credentials = ChildCredentials::broker_for_tests("wss://relay.example.com");
        let mut command = tokio::process::Command::new("not-spawned");
        for alias in LONG_LIVED_CREDENTIAL_ENV {
            command.env(alias, "LONG_LIVED_CANARY");
        }
        command.env("nostr_private_key", "CASE_ALIAS_CANARY");
        command.env("BUZZ_CAPABILITY_SURPRISE", "UNALLOWLISTED_CANARY");
        command.env("GIT_CONFIG_COUNT", "1");
        command.env("GIT_CONFIG_KEY_0", "nostr.keyfile");
        command.env("GIT_CONFIG_VALUE_0", "KEYFILE_PATH_CANARY");

        credentials.apply_to_command(&mut command);
        let configured: Vec<(String, Option<String>)> = command
            .as_std()
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();

        for alias in LONG_LIVED_CREDENTIAL_ENV {
            assert!(configured
                .iter()
                .any(|(name, value)| { name.eq_ignore_ascii_case(alias) && value.is_none() }));
        }
        assert!(!configured.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("nostr_private_key") && value.is_some()
        }));
        assert!(configured
            .iter()
            .any(|(name, value)| { name == "BUZZ_CAPABILITY_SURPRISE" && value.is_none() }));
        for name in ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"] {
            assert!(configured
                .iter()
                .any(|(configured_name, value)| configured_name == name && value.is_none()));
        }
        for required in PROJECTION_ENV {
            assert!(configured.iter().any(|(name, value)| {
                name == required && value.as_deref().is_some_and(|value| !value.is_empty())
            }));
        }
    }

    #[test]
    fn broker_child_environment_exposes_exactly_the_fixed_six_projection_and_no_long_lived_leak() {
        let credentials = ChildCredentials::broker_for_tests("wss://relay.example.com");
        let mut command = tokio::process::Command::new("not-spawned");
        for alias in LONG_LIVED_CREDENTIAL_ENV {
            command.env(alias, "LONG_LIVED_UPPER_CANARY");
            command.env(alias.to_ascii_lowercase(), "LONG_LIVED_LOWER_CANARY");
        }
        command.env("nostr_private_key", "CASE_ALIAS_CANARY");
        command.env("NOSTR_PRIVATE_KEY", "SECOND_CASE_ALIAS_CANARY");
        command.env("BUZZ_CAPABILITY_SURPRISE", "UNALLOWLISTED_CANARY");
        command.env("BUZZ_CAPABILITY_EXTRA", "UNALLOWLISTED_CANARY_2");
        command.env("GIT_CONFIG_COUNT", "1");
        command.env("GIT_CONFIG_KEY_0", "nostr.keyfile");
        command.env("GIT_CONFIG_VALUE_0", "KEYFILE_PATH_CANARY");
        command.env("GIT_CONFIG_KEY_1", "user.name");
        credentials.apply_to_command(&mut command);
        let configured: Vec<(String, Option<String>)> = command
            .as_std()
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for alias in LONG_LIVED_CREDENTIAL_ENV {
            assert!(
                !configured
                    .iter()
                    .any(|(name, value)| name.eq_ignore_ascii_case(alias) && value.is_some()),
                "long-lived alias must be absent: {alias}"
            );
        }
        for leaked in ["BUZZ_CAPABILITY_SURPRISE", "BUZZ_CAPABILITY_EXTRA"] {
            assert!(
                configured
                    .iter()
                    .any(|(name, value)| name == leaked && value.is_none()),
                "unknown capability var must be scrubbed: {leaked}"
            );
        }
        for git_var in [
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_CONFIG_KEY_1",
        ] {
            assert!(
                configured
                    .iter()
                    .any(|(name, value)| name == git_var && value.is_none()),
                "ephemeral git-config var must be scrubbed: {git_var}"
            );
        }
        let expected: [&str; 6] = PROJECTION_ENV;
        assert_eq!(
            expected.len(),
            6,
            "projection must be exactly the fixed six"
        );
        for required in expected {
            assert!(
                configured.iter().any(|(name, value)| {
                    name == required && value.as_deref().is_some_and(|value| !value.is_empty())
                }),
                "required fixed projection var missing: {required}"
            );
        }
        assert!(
            !configured.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("BUZZ_PRIVATE_KEY") && value.is_some()
            }),
            "BUZZ_PRIVATE_KEY must never appear in broker-child env"
        );
        let get = |name: &str| {
            configured
                .iter()
                .find(|(k, _)| k == name)
                .and_then(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert!(get("BUZZ_CAPABILITY_ENDPOINT").starts_with("tcp://127.0.0.1:"));
        assert_eq!(
            get("BUZZ_PUBLIC_KEY"),
            "dcfd242e557282d7a1e2cf2e6877522682f1e5c6156dc92ca7d90eaedd3b0f95"
        );
        assert!(get("BUZZ_RELAY_URL").starts_with("wss://relay.example.com"));
        assert!(get("BUZZ_CAPABILITY_EXPIRES_AT").parse::<i64>().is_ok());
        assert!(get("BUZZ_CAPABILITY_TOKEN").len() >= 32);
    }

    #[test]
    fn legacy_mode_does_not_rewrite_child_environment() {
        let credentials = ChildCredentials::LegacyEnv;
        let mut command = tokio::process::Command::new("not-spawned");
        command.env("BUZZ_PRIVATE_KEY", "LEGACY_CANARY");
        credentials.apply_to_command(&mut command);
        assert!(command.as_std().get_envs().any(|(name, value)| {
            name == "BUZZ_PRIVATE_KEY"
                && value.is_some_and(|value| value == OsStr::new("LEGACY_CANARY"))
        }));
    }
}
