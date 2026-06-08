use crate::statement::Statement;
use crate::hash::HashAlgorithm;

fn timestamp_to_iso8601(ts: u64) -> String {
    let secs_per_day: u64 = 86400;
    let days = ts / secs_per_day;
    let day_secs = ts % secs_per_day;

    let rata_die = days as i64 + 719468;
    let era = if rata_die >= 0 { rata_die } else { rata_die - 146096 } / 146097;
    let doe = rata_die - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let h = day_secs / 3600;
    let mi = (day_secs % 3600) / 60;
    let s = day_secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, h, mi, s
    )
}

fn format_hash_alg(alg: &HashAlgorithm) -> &'static str {
    match alg {
        HashAlgorithm::Sha256 => "SHA-256",
        HashAlgorithm::Sha384 => "SHA-384",
        HashAlgorithm::Sha512 => "SHA-512",
    }
}

pub fn audit(statement: &Statement) -> String {
    let type_str = statement.type_.as_str();
    let mut output = format!("Statement Audit\n├─ Type:    {}\n", type_str);

    match &statement.body {
        crate::statement::StatementBody::Provenance { hash, hash_alg, time, .. } => {
            let iso = timestamp_to_iso8601(*time);
            let parent_line = if let Some(ref p) = statement.parent {
                format!("├─ Parent:  {}\n", p)
            } else {
                String::new()
            };
            output.push_str(&format!(
                "├─ Origin:  {}\n\
                 {}├─ Hash:    {} ({})\n\
                 ├─ Time:    {} ({}) — advisory\n\
                 ├─ Key:     {}\n\
                 └─ Sig:     {}",
                statement.origin,
                parent_line,
                hash,
                format_hash_alg(hash_alg),
                iso,
                time,
                statement.key_b64,
                statement.sig_b64,
            ));
        }
        crate::statement::StatementBody::Revocation { revoked_key_b64, revoked_since, .. } => {
            let since_iso = timestamp_to_iso8601(*revoked_since);
            output.push_str(&format!(
                "├─ Origin:  {}\n\
                 ├─ Revoked: {} (key)\n\
                 ├─ Since:   {} ({})\n\
                 ├─ Key:     {} (signer)\n\
                 └─ Sig:     {}",
                statement.origin,
                revoked_key_b64,
                since_iso,
                revoked_since,
                statement.key_b64,
                statement.sig_b64,
            ));
        }
    }

    output
}

pub fn audit_with_verdict(statement: &Statement, verify_result: &crate::error::Result<()>) -> String {
    let verdict = match verify_result {
        Ok(()) => "VERIFIED".to_string(),
        Err(e) => format!("FAILED: {}", e),
    };
    format!("{}\n  Verdict: {}", audit(statement), verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_conversion() {
        assert_eq!(timestamp_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp_to_iso8601(1717776000), "2024-06-07T16:00:00Z");
        assert_eq!(timestamp_to_iso8601(1700000000), "2023-11-14T22:13:20Z");
    }
}
