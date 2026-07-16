use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, errors::ErrorKind, jwk::JwkSet,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::warn;
use url::Url;

const ACCESS_ASSERTION_HEADER: &str = "cf-access-jwt-assertion";
const MAX_ACCESS_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_JWKS_KEYS: usize = 64;
const MAX_ACCESS_TOKEN_LIFETIME_SECS: u64 = 24 * 60 * 60;
const CLOCK_LEEWAY_SECS: u64 = 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareAccessConfig {
    issuer: String,
    certs_url: Url,
    audience: String,
    allowed_emails: BTreeSet<String>,
}

impl CloudflareAccessConfig {
    pub fn from_env() -> Result<Option<Self>, CloudflareAccessConfigError> {
        let required = optional_env("RDASHBOARD_ACCESS_REQUIRED")?;
        let team_domain = optional_env("RDASHBOARD_ACCESS_TEAM_DOMAIN")?;
        let audience = optional_env("RDASHBOARD_ACCESS_AUDIENCE")?;
        let allowed_emails = optional_env("RDASHBOARD_ACCESS_ALLOWED_EMAILS")?;
        Self::from_values(required.as_deref(), team_domain, audience, allowed_emails)
    }

    fn from_values(
        required: Option<&str>,
        team_domain: Option<String>,
        audience: Option<String>,
        allowed_emails: Option<String>,
    ) -> Result<Option<Self>, CloudflareAccessConfigError> {
        let required = match required {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err(CloudflareAccessConfigError::InvalidRequiredFlag),
        };
        match (team_domain, audience, allowed_emails) {
            (None, None, None) if !required => Ok(None),
            (Some(team_domain), Some(audience), Some(allowed_emails)) => {
                Self::new(&team_domain, &audience, &allowed_emails).map(Some)
            }
            _ => Err(CloudflareAccessConfigError::Incomplete),
        }
    }

    pub fn new(
        team_domain: &str,
        audience: &str,
        allowed_emails: &str,
    ) -> Result<Self, CloudflareAccessConfigError> {
        let parsed =
            Url::parse(team_domain).map_err(|_| CloudflareAccessConfigError::InvalidTeamDomain)?;
        let host = parsed
            .host_str()
            .ok_or(CloudflareAccessConfigError::InvalidTeamDomain)?;
        let Some(team_name) = host.strip_suffix(".cloudflareaccess.com") else {
            return Err(CloudflareAccessConfigError::InvalidTeamDomain);
        };
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.port().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !valid_team_name(team_name)
        {
            return Err(CloudflareAccessConfigError::InvalidTeamDomain);
        }
        if audience.is_empty()
            || audience.len() > 256
            || !audience
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CloudflareAccessConfigError::InvalidAudience);
        }
        let issuer = format!("https://{host}");
        if team_domain != issuer {
            return Err(CloudflareAccessConfigError::InvalidTeamDomain);
        }
        let certs_url = Url::parse(&format!("{issuer}/cdn-cgi/access/certs"))
            .map_err(|_| CloudflareAccessConfigError::InvalidTeamDomain)?;
        let allowed_emails = parse_allowed_emails(allowed_emails)?;
        Ok(Self {
            issuer,
            certs_url,
            audience: audience.to_owned(),
            allowed_emails,
        })
    }
}

#[derive(Clone)]
pub struct CloudflareAccessVerifier {
    config: CloudflareAccessConfig,
    client: reqwest::Client,
    keys: Arc<RwLock<BTreeMap<String, DecodingKey>>>,
    refresh: Arc<Mutex<()>>,
}

impl std::fmt::Debug for CloudflareAccessVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloudflareAccessVerifier")
            .field("issuer", &"[redacted]")
            .field("audience", &"[redacted]")
            .field("allowed_emails", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl CloudflareAccessVerifier {
    pub async fn connect(
        config: CloudflareAccessConfig,
    ) -> Result<Self, CloudflareAccessVerificationError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .user_agent("rdashboard-access-verifier/1")
            .build()
            .map_err(|_| CloudflareAccessVerificationError::Unavailable)?;
        let verifier = Self {
            config,
            client,
            keys: Arc::new(RwLock::new(BTreeMap::new())),
            refresh: Arc::new(Mutex::new(())),
        };
        verifier.refresh_keys().await?;
        Ok(verifier)
    }

    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<CloudflareAccessIdentity, CloudflareAccessVerificationError> {
        let mut assertions = headers.get_all(ACCESS_ASSERTION_HEADER).iter();
        let assertion = assertions
            .next()
            .ok_or(CloudflareAccessVerificationError::Denied(
                "assertion_missing",
            ))?;
        if assertions.next().is_some() {
            return Err(CloudflareAccessVerificationError::Denied(
                "assertion_duplicated",
            ));
        }
        let assertion = assertion
            .to_str()
            .map_err(|_| CloudflareAccessVerificationError::Denied("assertion_not_ascii"))?;
        if assertion.is_empty() || assertion.len() > MAX_ACCESS_TOKEN_BYTES {
            return Err(CloudflareAccessVerificationError::Denied(
                "assertion_size_invalid",
            ));
        }
        self.verify(assertion).await
    }

    async fn verify(
        &self,
        assertion: &str,
    ) -> Result<CloudflareAccessIdentity, CloudflareAccessVerificationError> {
        let header = decode_header(assertion)
            .map_err(|_| CloudflareAccessVerificationError::Denied("header_invalid"))?;
        if header.alg != Algorithm::RS256 {
            return Err(CloudflareAccessVerificationError::Denied(
                "header_algorithm_invalid",
            ));
        }
        if header
            .typ
            .as_deref()
            .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("JWT"))
        {
            return Err(CloudflareAccessVerificationError::Denied(
                "header_type_invalid",
            ));
        }
        let key_id = header.kid.filter(|value| valid_key_id(value)).ok_or(
            CloudflareAccessVerificationError::Denied("header_key_id_invalid"),
        )?;
        let key = self.key(&key_id).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[self.config.audience.as_str()]);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.validate_nbf = true;
        validation.leeway = CLOCK_LEEWAY_SECS;
        validation.required_spec_claims = ["aud", "email", "exp", "iat", "iss", "nbf", "sub"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let token =
            decode::<CloudflareAccessClaims>(assertion, &key, &validation).map_err(|error| {
                CloudflareAccessVerificationError::Denied(jwt_validation_reason(&error))
            })?;
        let claims = token.claims;
        let now = unix_time_secs().map_err(|_| CloudflareAccessVerificationError::Unavailable)?;
        let email = normalize_email(&claims.email).ok_or(
            CloudflareAccessVerificationError::Denied("email_claim_invalid"),
        )?;
        if claims.token_type != "app" {
            return Err(CloudflareAccessVerificationError::Denied(
                "token_type_invalid",
            ));
        }
        if claims.subject.is_empty() || claims.subject.len() > 256 {
            return Err(CloudflareAccessVerificationError::Denied(
                "subject_claim_invalid",
            ));
        }
        if claims.issued_at > now.saturating_add(CLOCK_LEEWAY_SECS) {
            return Err(CloudflareAccessVerificationError::Denied(
                "issued_at_in_future",
            ));
        }
        if claims.not_before > now.saturating_add(CLOCK_LEEWAY_SECS) {
            return Err(CloudflareAccessVerificationError::Denied(
                "not_before_in_future",
            ));
        }
        if claims.issued_at > claims.expires_at || claims.not_before > claims.expires_at {
            return Err(CloudflareAccessVerificationError::Denied(
                "token_time_order_invalid",
            ));
        }
        if claims.expires_at <= now {
            return Err(CloudflareAccessVerificationError::Denied("token_expired"));
        }
        if now.saturating_sub(claims.issued_at) > MAX_ACCESS_TOKEN_LIFETIME_SECS
            || claims.expires_at.saturating_sub(claims.issued_at) > MAX_ACCESS_TOKEN_LIFETIME_SECS
        {
            return Err(CloudflareAccessVerificationError::Denied(
                "token_lifetime_invalid",
            ));
        }
        if !claims
            .audience
            .iter()
            .any(|value| value == &self.config.audience)
        {
            return Err(CloudflareAccessVerificationError::Denied(
                "audience_mismatch",
            ));
        }
        if claims.issuer != self.config.issuer {
            return Err(CloudflareAccessVerificationError::Denied("issuer_mismatch"));
        }
        if !self.config.allowed_emails.contains(&email) {
            return Err(CloudflareAccessVerificationError::Denied(
                "email_not_allowed",
            ));
        }
        Ok(CloudflareAccessIdentity {
            email,
            subject: claims.subject,
            expires_at: claims.expires_at,
        })
    }

    async fn key(&self, key_id: &str) -> Result<DecodingKey, CloudflareAccessVerificationError> {
        if let Some(key) = self.keys.read().await.get(key_id).cloned() {
            return Ok(key);
        }
        let _guard = self.refresh.lock().await;
        if let Some(key) = self.keys.read().await.get(key_id).cloned() {
            return Ok(key);
        }
        self.refresh_keys().await?;
        self.keys.read().await.get(key_id).cloned().ok_or(
            CloudflareAccessVerificationError::Denied("signing_key_unknown"),
        )
    }

    async fn refresh_keys(&self) -> Result<(), CloudflareAccessVerificationError> {
        let mut response = self
            .client
            .get(self.config.certs_url.clone())
            .send()
            .await
            .map_err(|_| CloudflareAccessVerificationError::Unavailable)?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(CloudflareAccessVerificationError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| CloudflareAccessVerificationError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
                return Err(CloudflareAccessVerificationError::Unavailable);
            }
            bytes.extend_from_slice(&chunk);
        }
        let set: JwkSet = serde_json::from_slice(&bytes)
            .map_err(|_| CloudflareAccessVerificationError::Unavailable)?;
        if set.keys.is_empty() || set.keys.len() > MAX_JWKS_KEYS {
            return Err(CloudflareAccessVerificationError::Unavailable);
        }
        let mut keys = BTreeMap::new();
        for key in &set.keys {
            let key_id = key
                .common
                .key_id
                .as_deref()
                .filter(|value| valid_key_id(value))
                .ok_or(CloudflareAccessVerificationError::Unavailable)?;
            let decoding_key = DecodingKey::from_jwk(key)
                .map_err(|_| CloudflareAccessVerificationError::Unavailable)?;
            if keys.insert(key_id.to_owned(), decoding_key).is_some() {
                return Err(CloudflareAccessVerificationError::Unavailable);
            }
        }
        *self.keys.write().await = keys;
        Ok(())
    }

    #[cfg(test)]
    fn with_test_key(config: CloudflareAccessConfig, key_id: &str, key: DecodingKey) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
            keys: Arc::new(RwLock::new(BTreeMap::from([(key_id.to_owned(), key)]))),
            refresh: Arc::new(Mutex::new(())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudflareAccessIdentity {
    pub email: String,
    pub subject: String,
    pub expires_at: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct CloudflareAccessClaims {
    #[serde(rename = "aud")]
    audience: Vec<String>,
    email: String,
    #[serde(rename = "exp")]
    expires_at: u64,
    #[serde(rename = "iat")]
    issued_at: u64,
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "nbf")]
    not_before: u64,
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "type")]
    token_type: String,
}

pub async fn require_cloudflare_access(
    State(verifier): State<Arc<CloudflareAccessVerifier>>,
    mut request: Request,
    next: Next,
) -> Response {
    match verifier.authenticate(request.headers()).await {
        Ok(identity) => {
            request.headers_mut().remove(ACCESS_ASSERTION_HEADER);
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(CloudflareAccessVerificationError::Denied(reason)) => {
            warn!(
                denial_reason = reason,
                "Cloudflare Access authorization denied"
            );
            access_problem(
                StatusCode::FORBIDDEN,
                "access_denied",
                "Cloudflare Access authorization is required.",
            )
        }
        Err(CloudflareAccessVerificationError::Unavailable) => access_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "access_verification_unavailable",
            "Cloudflare Access verification is temporarily unavailable.",
        ),
    }
}

fn access_problem(status: StatusCode, code: &'static str, detail: &'static str) -> Response {
    let mut response = (status, Json(AccessProblem { code, detail })).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}

#[derive(Serialize)]
struct AccessProblem {
    code: &'static str,
    detail: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CloudflareAccessVerificationError {
    #[error("Cloudflare Access denied the request: {0}")]
    Denied(&'static str),
    #[error("Cloudflare Access verification is unavailable")]
    Unavailable,
}

fn jwt_validation_reason(error: &jsonwebtoken::errors::Error) -> &'static str {
    match error.kind() {
        ErrorKind::InvalidSignature => "signature_invalid",
        ErrorKind::MissingRequiredClaim(claim) => match claim.as_str() {
            "aud" => "audience_claim_missing",
            "email" => "email_claim_missing",
            "exp" => "expires_at_claim_missing",
            "iat" => "issued_at_claim_missing",
            "iss" => "issuer_claim_missing",
            "nbf" => "not_before_claim_missing",
            "sub" => "subject_claim_missing",
            _ => "required_claim_missing",
        },
        ErrorKind::InvalidClaimFormat(claim) => match claim.as_str() {
            "aud" => "audience_claim_format_invalid",
            "exp" => "expires_at_claim_format_invalid",
            "iss" => "issuer_claim_format_invalid",
            "nbf" => "not_before_claim_format_invalid",
            "sub" => "subject_claim_format_invalid",
            _ => "claim_format_invalid",
        },
        ErrorKind::ExpiredSignature => "token_expired",
        ErrorKind::InvalidIssuer => "issuer_mismatch",
        ErrorKind::InvalidAudience => "audience_mismatch",
        ErrorKind::InvalidSubject => "subject_mismatch",
        ErrorKind::ImmatureSignature => "not_before_in_future",
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => "algorithm_invalid",
        ErrorKind::InvalidToken
        | ErrorKind::Base64(_)
        | ErrorKind::Json(_)
        | ErrorKind::Utf8(_) => "token_encoding_invalid",
        ErrorKind::InvalidEcdsaKey
        | ErrorKind::InvalidEddsaKey
        | ErrorKind::InvalidRsaKey(_)
        | ErrorKind::InvalidKeyFormat
        | ErrorKind::MissingAlgorithm
        | ErrorKind::Provider(_) => "verification_key_invalid",
        _ => "token_validation_failed",
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CloudflareAccessConfigError {
    #[error("Cloudflare Access configuration is incomplete")]
    Incomplete,
    #[error("RDASHBOARD_ACCESS_REQUIRED must be true or false")]
    InvalidRequiredFlag,
    #[error("Cloudflare Access team domain is invalid")]
    InvalidTeamDomain,
    #[error("Cloudflare Access audience is invalid")]
    InvalidAudience,
    #[error("Cloudflare Access allowed email list is invalid")]
    InvalidAllowedEmails,
    #[error("Cloudflare Access environment configuration is not valid Unicode")]
    NonUnicode,
}

fn optional_env(name: &str) -> Result<Option<String>, CloudflareAccessConfigError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CloudflareAccessConfigError::NonUnicode),
    }
}

fn valid_team_name(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_key_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn parse_allowed_emails(value: &str) -> Result<BTreeSet<String>, CloudflareAccessConfigError> {
    let emails = value
        .split(',')
        .map(str::trim)
        .map(normalize_email)
        .collect::<Option<BTreeSet<_>>>()
        .ok_or(CloudflareAccessConfigError::InvalidAllowedEmails)?;
    if emails.is_empty() || emails.len() > 32 {
        return Err(CloudflareAccessConfigError::InvalidAllowedEmails);
    }
    Ok(emails)
}

fn normalize_email(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 254
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value.chars().filter(|character| *character == '@').count() != 1
        || value.starts_with('@')
        || value.ends_with('@')
        || value.contains(char::is_whitespace)
    {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn unix_time_secs() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};
    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::*;

    const TEST_PRIVATE_KEY: &[u8] = br"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqcUQzqQX0VghH
ibMTBABmT8KmBUKCJq89ViX3NQPgPr9kDsdFVQo312+Gh2sD+Pj07l9DspgCxlgK
HEj8oM9xgNf0rOir6LGjqLHqAbGfYtIWys3bxGecXMRG1PBMigyq8VHC4zxgcVwD
lTp4vH6H1c34x9NKkoA7dkmVlh8dfCWJevIkyLQCREq5z2iT9WbWFK4PtvhRjHy3
XmPZOaYIuPmzq6h6ZlGhEAThXwmKBh1d33I6zDqVec/Wl3pWEIFjXdnp+MbdzfJz
8V8oLG6SeGtKGxW02s3VZ1VV6KiD6wNGEgm7Q0+3TeYKhFs7lsMy89TvvUdZ+gVz
BeT65mgzAgMBAAECggEAQ1ljekhhTnXKar46MRrlL4h34VN1vukbWNDYSrE7uVoC
Fb8TNc3PLlamPpH3EwhIE7y3jxAcqggHFOOtYYoHvpGLhCbo/7kArKtFtjJ6JgGO
A6yaoKsgx/QOKPEOjSgFrmySAsD5BCD3G4FVrAzLsNAmxhXr4201V4m7tOyvmd3l
QQ/7fQVuRk6MxinG/Fgvtghi8DGBhUdO9uirt0VWe+lnVqGy0aJfDPpKaJ/NIbVU
p1STPRsQvq/7RmS5P4fEsSfN3jp4sWTurQHnZDemdm8Yu6czoZEUf9o6y84veDOW
N7BEZg16i4o2sjtW/P1xRMAs79qRJ9qW6qCFRRNMeQKBgQDluS/m2SPIAH3W5kDI
YcOxBbBlhtrpwvlujW5kyabIeLSgv5406KhwBYFy8vra+c/57iNMIUfmr0oI2sj9
6PZoczGTSVLyb0p2alX7At5KjPZP3ilPCFRTaxhnHVKvFd8E5C1PXGQQWyNZSH92
s4ah0D3KR9btDRQg+uF/r5/9KwKBgQC98DOC3FMISr3qXwvKJN3nwOFie7elfGvg
bScTvzBtk7wrwaajQjYA0A92nQvfRELyS0UfKIPhIYHfMIQgOLfuoQPKIQ/kZeq7
pXsZ54U51ULtXNSEYQrdPcggGRc+j3HJGMfJjneP+eRPnJPQrt6G/y3vpftjlWpo
8V0icoKNGQKBgEjTNERSge1deoct50ue8pKj4w/MeImyrbBGVcDNzHmxClILbPQI
7ZzVofv221+f4jaxL69qvYh7+VRlR2J2/+aM3iJ7FDiW31w6yZcRibbIiS04mI/d
bB4lzU6jFRs8K785NsP53h7xRXuAaCgRMZUKlwwRSilMBB2Qavw3iNiRAoGAb1D8
T4Bi5WQwg9Bqb3FF4FJJhVdunP0bmC9AjLErZ70Ctj5LNDlUvwsxVNnboGE4Pxpg
C0/KYsIphC3B8cRr/928A9V2o+wbMxhb2iW3Ddrv237hSig5nspbpHwwBEk7bZkp
VfY6GlZhOUtR0ib6YfHh8Sa8+3MRJyn15H9qBdkCgYEAt+38xfIXBxaE8dozqXBg
SiaV4ieWLhWh0CJpqF4INPA5jNbTQHK8FyLIWmQehXtRCFqR20xswHGtt3Egestj
IMD1SWARM+PWa3enSSxpEJIqJPUiMb+oRnVrfGf1KuGHqzA6JvZQJ9hnJtLQnKYV
WoPqcwghU2zc3VTGrk95idU=
-----END PRIVATE KEY-----";
    const TEST_PUBLIC_KEY: &[u8] = br"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqnFEM6kF9FYIR4mzEwQA
Zk/CpgVCgiavPVYl9zUD4D6/ZA7HRVUKN9dvhodrA/j49O5fQ7KYAsZYChxI/KDP
cYDX9Kzoq+ixo6ix6gGxn2LSFsrN28RnnFzERtTwTIoMqvFRwuM8YHFcA5U6eLx+
h9XN+MfTSpKAO3ZJlZYfHXwliXryJMi0AkRKuc9ok/Vm1hSuD7b4UYx8t15j2Tmm
CLj5s6uoemZRoRAE4V8JigYdXd9yOsw6lXnP1pd6VhCBY13Z6fjG3c3yc/FfKCxu
knhrShsVtNrN1WdVVeiog+sDRhIJu0NPt03mCoRbO5bDMvPU771HWfoFcwXk+uZo
MwIDAQAB
-----END PUBLIC KEY-----";

    fn config() -> CloudflareAccessConfig {
        CloudflareAccessConfig::new(
            "https://example.cloudflareaccess.com",
            "dashboard-audience",
            "operator@example.com",
        )
        .unwrap_or_else(|error| panic!("config: {error}"))
    }

    fn claims(now: u64) -> CloudflareAccessClaims {
        CloudflareAccessClaims {
            audience: vec!["dashboard-audience".to_owned()],
            email: "operator@example.com".to_owned(),
            expires_at: now + 300,
            issued_at: now,
            issuer: "https://example.cloudflareaccess.com".to_owned(),
            not_before: now,
            subject: "access-user-1".to_owned(),
            token_type: "app".to_owned(),
        }
    }

    fn token(claims: &CloudflareAccessClaims) -> String {
        token_with_type(claims, Some("JWT"))
    }

    fn token_with_type(claims: &CloudflareAccessClaims, token_type: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_owned());
        header.typ = token_type.map(str::to_owned);
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY)
                .unwrap_or_else(|error| panic!("private key: {error}")),
        )
        .unwrap_or_else(|error| panic!("token: {error}"))
    }

    fn verifier() -> CloudflareAccessVerifier {
        CloudflareAccessVerifier::with_test_key(
            config(),
            "test-key",
            DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY)
                .unwrap_or_else(|error| panic!("public key: {error}")),
        )
    }

    #[tokio::test]
    async fn access_token_type_is_optional_and_case_insensitive_when_present() {
        let verifier = verifier();
        let now = unix_time_secs().unwrap_or_else(|error| panic!("clock: {error}"));
        for token_type in [None, Some("JWT"), Some("jwt")] {
            let encoded = token_with_type(&claims(now), token_type);
            let mut headers = HeaderMap::new();
            headers.insert(
                ACCESS_ASSERTION_HEADER,
                HeaderValue::from_str(&encoded).unwrap_or_else(|error| panic!("header: {error}")),
            );
            assert!(verifier.authenticate(&headers).await.is_ok());
        }

        let encoded = token_with_type(&claims(now), Some("not-a-jwt"));
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCESS_ASSERTION_HEADER,
            HeaderValue::from_str(&encoded).unwrap_or_else(|error| panic!("header: {error}")),
        );
        assert_eq!(
            verifier.authenticate(&headers).await,
            Err(CloudflareAccessVerificationError::Denied(
                "header_type_invalid"
            ))
        );
    }

    #[test]
    fn jwt_validation_errors_map_to_fixed_non_sensitive_categories() {
        use jsonwebtoken::errors::{Error, new_error};

        let assert_reason = |error: Error, expected_reason| {
            let reason = jwt_validation_reason(&error);
            assert_eq!(reason, expected_reason);
            assert!(
                reason
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        };
        for (claim, expected_reason) in [
            ("aud", "audience_claim_missing"),
            ("email", "email_claim_missing"),
            ("exp", "expires_at_claim_missing"),
            ("iat", "issued_at_claim_missing"),
            ("iss", "issuer_claim_missing"),
            ("nbf", "not_before_claim_missing"),
            ("sub", "subject_claim_missing"),
            ("sensitive-future-claim", "required_claim_missing"),
        ] {
            assert_reason(
                new_error(ErrorKind::MissingRequiredClaim(claim.to_owned())),
                expected_reason,
            );
        }
        for (claim, expected_reason) in [
            ("aud", "audience_claim_format_invalid"),
            ("exp", "expires_at_claim_format_invalid"),
            ("iss", "issuer_claim_format_invalid"),
            ("nbf", "not_before_claim_format_invalid"),
            ("sub", "subject_claim_format_invalid"),
            ("sensitive-future-claim", "claim_format_invalid"),
        ] {
            assert_reason(
                new_error(ErrorKind::InvalidClaimFormat(claim.to_owned())),
                expected_reason,
            );
        }
        for (error, expected_reason) in [
            (new_error(ErrorKind::InvalidSignature), "signature_invalid"),
            (new_error(ErrorKind::ExpiredSignature), "token_expired"),
            (new_error(ErrorKind::InvalidIssuer), "issuer_mismatch"),
            (new_error(ErrorKind::InvalidAudience), "audience_mismatch"),
            (new_error(ErrorKind::InvalidSubject), "subject_mismatch"),
            (
                new_error(ErrorKind::ImmatureSignature),
                "not_before_in_future",
            ),
            (new_error(ErrorKind::InvalidAlgorithm), "algorithm_invalid"),
            (
                new_error(ErrorKind::InvalidAlgorithmName),
                "algorithm_invalid",
            ),
            (new_error(ErrorKind::InvalidToken), "token_encoding_invalid"),
            (
                new_error(ErrorKind::InvalidRsaKey("sensitive-detail".to_owned())),
                "verification_key_invalid",
            ),
            (
                new_error(ErrorKind::Provider("sensitive-detail".to_owned())),
                "verification_key_invalid",
            ),
            (
                new_error(ErrorKind::RsaFailedSigning),
                "token_validation_failed",
            ),
            (
                new_error(ErrorKind::Signing("sensitive-detail".to_owned())),
                "token_validation_failed",
            ),
        ] {
            assert_reason(error, expected_reason);
        }
    }

    #[test]
    fn access_config_rejects_partial_origins_and_ambiguous_email_lists() {
        assert_eq!(
            CloudflareAccessConfig::from_values(Some("true"), None, None, None),
            Err(CloudflareAccessConfigError::Incomplete)
        );
        assert_eq!(
            CloudflareAccessConfig::from_values(Some("yes"), None, None, None),
            Err(CloudflareAccessConfigError::InvalidRequiredFlag)
        );
        assert_eq!(
            CloudflareAccessConfig::from_values(None, None, None, None),
            Ok(None)
        );
        for domain in [
            "http://example.cloudflareaccess.com",
            "https://example.cloudflareaccess.com/path",
            "https://example.cloudflareaccess.com.evil.test",
            "https://EXAMPLE.cloudflareaccess.com",
        ] {
            assert!(CloudflareAccessConfig::new(domain, "audience", "a@example.com").is_err());
        }
        for emails in ["", "a@example.com,,b@example.com", "not-an-email"] {
            assert!(
                CloudflareAccessConfig::new(
                    "https://example.cloudflareaccess.com",
                    "audience",
                    emails,
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn exact_access_identity_is_signature_audience_issuer_and_email_bound() {
        let verifier = verifier();
        let now = unix_time_secs().unwrap_or_else(|error| panic!("clock: {error}"));
        let exact = token(&claims(now));
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCESS_ASSERTION_HEADER,
            HeaderValue::from_str(&exact).unwrap_or_else(|error| panic!("header: {error}")),
        );
        let identity = verifier
            .authenticate(&headers)
            .await
            .unwrap_or_else(|error| panic!("authenticate: {error}"));
        assert_eq!(identity.email, "operator@example.com");
        assert_eq!(identity.subject, "access-user-1");

        let mut wrong_audience = claims(now);
        wrong_audience.audience = vec!["other-application".to_owned()];
        let mut wrong_email = claims(now);
        wrong_email.email = "intruder@example.com".to_owned();
        let mut wrong_type = claims(now);
        wrong_type.token_type = "org".to_owned();
        for (rejected, expected_reason) in [
            (wrong_audience, "audience_mismatch"),
            (wrong_email, "email_not_allowed"),
            (wrong_type, "token_type_invalid"),
        ] {
            let mut rejected_headers = HeaderMap::new();
            rejected_headers.insert(
                ACCESS_ASSERTION_HEADER,
                HeaderValue::from_str(&token(&rejected))
                    .unwrap_or_else(|error| panic!("header: {error}")),
            );
            assert_eq!(
                verifier.authenticate(&rejected_headers).await,
                Err(CloudflareAccessVerificationError::Denied(expected_reason))
            );
        }
    }

    #[tokio::test]
    async fn access_header_is_required_once_and_tokens_have_a_bounded_lifetime() {
        let verifier = verifier();
        assert_eq!(
            verifier.authenticate(&HeaderMap::new()).await,
            Err(CloudflareAccessVerificationError::Denied(
                "assertion_missing"
            ))
        );
        let now = unix_time_secs().unwrap_or_else(|error| panic!("clock: {error}"));
        let mut too_long = claims(now);
        too_long.expires_at = now + MAX_ACCESS_TOKEN_LIFETIME_SECS + 1;
        let value = HeaderValue::from_str(&token(&too_long))
            .unwrap_or_else(|error| panic!("header: {error}"));
        let mut duplicated = HeaderMap::new();
        duplicated.append(ACCESS_ASSERTION_HEADER, value.clone());
        duplicated.append(ACCESS_ASSERTION_HEADER, value);
        assert_eq!(
            verifier.authenticate(&duplicated).await,
            Err(CloudflareAccessVerificationError::Denied(
                "assertion_duplicated"
            ))
        );
    }
}
