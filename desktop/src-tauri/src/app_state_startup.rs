use nostr::Keys;

/// Parse the optional development/CI identity override.
pub(super) fn identity_from_env() -> Option<Keys> {
    match std::env::var("BUZZ_PRIVATE_KEY") {
        Ok(nsec) => match Keys::parse(nsec.trim()) {
            Ok(keys) => Some(keys),
            Err(error) => {
                eprintln!("buzz-desktop: invalid BUZZ_PRIVATE_KEY: {error}");
                None
            }
        },
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("buzz-desktop: BUZZ_PRIVATE_KEY contains invalid UTF-8");
            None
        }
        Err(std::env::VarError::NotPresent) => None,
    }
}

/// Build the fail-closed, no-redirect client used for authenticated relay
/// media fetches. Redirects must remain disabled so a minted Authorization
/// header can never be forwarded away from the validated relay origin.
pub fn build_media_fetch_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .pool_idle_timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(1)
        .redirect(reqwest::redirect::Policy::none())
        .build()
}
