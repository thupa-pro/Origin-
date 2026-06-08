use crate::statement::Statement;

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

fn format_hash_alg(alg: &crate::hash::HashAlgorithm) -> &'static str {
    match alg {
        crate::hash::HashAlgorithm::Sha256 => "SHA-256",
        crate::hash::HashAlgorithm::Sha384 => "SHA-384",
        crate::hash::HashAlgorithm::Sha512 => "SHA-512",
    }
}

/// Produce a human-readable audit report of a provenance statement.
pub fn audit(statement: &Statement) -> String {
    let iso = timestamp_to_iso8601(statement.time);
    let parent_line = if let Some(ref p) = statement.parent {
        format!("├─ Parent:  {}\n", p)
    } else {
        String::new()
    };
    format!(
        "Statement Audit\n\
         ├─ Origin:  {}\n\
         {}├─ Hash:    {} ({})\n\
         ├─ Time:    {} ({}) — advisory\n\
         ├─ Key:     {}\n\
         └─ Sig:     {}",
        statement.origin,
        parent_line,
        statement.hash,
        format_hash_alg(&statement.hash_alg),
        iso,
        statement.time,
        statement.key_b64,
        statement.sig_b64,
    )
}

/// Produce a human-readable audit report with verification verdict appended.
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
