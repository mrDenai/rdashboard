use regex::Regex;

use super::{EvidenceDigest, LOG_EVENT_CAP_BYTES};

const REDACTED: &str = "[REDACTED]";
const TRUNCATED: &str = "\n[TRUNCATED]";
const REDACTION_RULESET_V2: &str = concat!(
    "rdashboard.redaction-ruleset.v2;",
    "known-exact;private-key;bearer;key-value;jwt;provider-key;ansi;control"
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactionResult {
    pub text: String,
    pub replacement_count: u64,
}

#[derive(Debug)]
pub struct Redactor {
    known_secrets: Vec<String>,
    private_key: Regex,
    bearer: Regex,
    key_value: Regex,
    jwt: Regex,
    provider_key: Regex,
    ansi_escape: Regex,
}

impl Redactor {
    pub fn new<I, S>(known_secrets: I) -> Result<Self, regex::Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut known_secrets = known_secrets
            .into_iter()
            .map(Into::into)
            .filter(|secret| secret.len() >= 4)
            .collect::<Vec<_>>();
        known_secrets.sort_by_key(|right| std::cmp::Reverse(right.len()));
        known_secrets.dedup();

        Ok(Self {
            known_secrets,
            private_key: Regex::new(
                r"(?s)-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
            )?,
            bearer: Regex::new(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")?,
            key_value: Regex::new(
                r#"(?i)\b(authorization|token|secret|password|passwd|api[_-]?key)(\s*[:=]\s*)([^\s,;"']{4,})"#,
            )?,
            jwt: Regex::new(r"\beyJ[a-zA-Z0-9_-]{4,}\.[a-zA-Z0-9_-]{4,}\.[a-zA-Z0-9_-]{4,}\b")?,
            provider_key: Regex::new(r"\b(?:sk-|gh[pousr]_|AIza)[a-zA-Z0-9_-]{12,}\b")?,
            ansi_escape: Regex::new(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])")?,
        })
    }

    pub fn redact(&self, input: &str) -> String {
        self.redact_with_evidence(input).text
    }

    pub fn redact_with_evidence(&self, input: &str) -> RedactionResult {
        let ansi_count = self.ansi_escape.find_iter(input).count();
        let without_ansi = self.ansi_escape.replace_all(input, "");
        let mut control_count = 0_usize;
        let mut output = without_ansi
            .chars()
            .filter(|character| {
                let retained = *character == '\n'
                    || *character == '\t'
                    || (!character.is_control() && *character != '\u{7f}');
                if !retained {
                    control_count = control_count.saturating_add(1);
                }
                retained
            })
            .collect::<String>();
        let mut replacement_count = ansi_count.saturating_add(control_count);
        for secret in &self.known_secrets {
            replacement_count = replacement_count.saturating_add(output.matches(secret).count());
            output = output.replace(secret, REDACTED);
        }
        replacement_count =
            replacement_count.saturating_add(self.private_key.find_iter(&output).count());
        output = self.private_key.replace_all(&output, REDACTED).into_owned();
        replacement_count =
            replacement_count.saturating_add(self.bearer.find_iter(&output).count());
        output = self
            .bearer
            .replace_all(&output, "Bearer [REDACTED]")
            .into_owned();
        replacement_count =
            replacement_count.saturating_add(self.key_value.find_iter(&output).count());
        output = self
            .key_value
            .replace_all(&output, "$1$2[REDACTED]")
            .into_owned();
        replacement_count = replacement_count.saturating_add(self.jwt.find_iter(&output).count());
        output = self.jwt.replace_all(&output, REDACTED).into_owned();
        replacement_count =
            replacement_count.saturating_add(self.provider_key.find_iter(&output).count());
        output = self
            .provider_key
            .replace_all(&output, REDACTED)
            .into_owned();
        RedactionResult {
            text: output,
            replacement_count: u64::try_from(replacement_count).unwrap_or(u64::MAX),
        }
    }

    pub fn ruleset_digest(&self) -> EvidenceDigest {
        EvidenceDigest::sha256(REDACTION_RULESET_V2)
    }

    pub fn redact_log_event(&self, input: &str) -> String {
        truncate_utf8(&self.redact(input), LOG_EVENT_CAP_BYTES, TRUNCATED)
    }
}

pub fn truncate_utf8(input: &str, max_bytes: usize, suffix: &str) -> String {
    if input.len() <= max_bytes {
        return input.to_owned();
    }
    let suffix_len = suffix.len().min(max_bytes);
    let mut boundary = max_bytes - suffix_len;
    while boundary > 0 && !input.is_char_boundary(boundary) {
        boundary -= 1;
    }
    let mut output = String::with_capacity(max_bytes);
    output.push_str(&input[..boundary]);
    output.push_str(&suffix[..suffix_len]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_and_structural_secrets_without_erasing_the_failure() {
        let redactor = Redactor::new(["exact-private-value"]).unwrap_or_else(|error| {
            panic!("static redaction regexes must compile: {error}");
        });
        let input = "deploy failed: token=top-secret Bearer abcdefghijk exact-private-value";
        let output = redactor.redact(input);

        assert!(output.starts_with("deploy failed:"));
        assert!(!output.contains("top-secret"));
        assert!(!output.contains("abcdefghijk"));
        assert!(!output.contains("exact-private-value"));
    }

    #[test]
    fn truncation_keeps_valid_utf8_and_hard_cap() {
        let input = "я".repeat(LOG_EVENT_CAP_BYTES);
        let output = truncate_utf8(&input, 101, TRUNCATED);
        assert!(output.len() <= 101);
        assert!(output.ends_with(TRUNCATED));
    }

    #[test]
    fn strips_terminal_controls_and_reports_redaction_evidence() {
        let redactor = Redactor::new(["known-secret"]).unwrap_or_else(|error| panic!("{error}"));
        let result = redactor.redact_with_evidence(
            "\u{1b}[31mfailed\u{1b}[0m\u{7} token=private-value known-secret",
        );

        assert_eq!(result.replacement_count, 5);
        assert_eq!(result.text, "failed token=[REDACTED] [REDACTED]");
        assert_eq!(redactor.ruleset_digest().as_str().len(), 64);
    }
}
