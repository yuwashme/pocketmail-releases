//! Unix seconds <-> RFC 3501 `date-time` / `date-text`, all UTC. Calendar maths after Howard
//! Hinnant's `days_from_civil` / `civil_from_days` (proleptic Gregorian, any year).

const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const DAY: i64 = 86_400;

/// Days since 1970-01-01 for a civil date (month 1..=12).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// (year, month 1..=12, day 1..=31) of a day number since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Broken-down UTC time: (year, month, day, hour, minute, second).
pub fn civil(unix: i64) -> (i64, u32, u32, u32, u32, u32) {
    let (y, m, d) = civil_from_days(unix.div_euclid(DAY));
    let s = unix.rem_euclid(DAY);
    (y, m, d, (s / 3600) as u32, (s / 60 % 60) as u32, (s % 60) as u32)
}

/// "yyyymm" of the UTC month containing `unix` (blob directory names).
pub fn yyyymm(unix: i64) -> String {
    let (y, m, ..) = civil(unix);
    format!("{y:04}{m:02}")
}

/// "2026-11-05T09:14:00Z" (log lines).
pub fn format_rfc3339(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// RFC 9110 IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT" (HTTP Date header).
pub fn format_http_date(unix: i64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let (y, mo, d, h, mi, s) = civil(unix);
    let weekday = WEEKDAYS[unix.div_euclid(DAY).rem_euclid(7) as usize];
    format!("{weekday}, {d:02} {} {y:04} {h:02}:{mi:02}:{s:02} GMT", MONTHS[mo as usize - 1])
}

/// RFC 3501 `date-time` without the surrounding DQUOTEs: day is `date-day-fixed`
/// (space-padded: " 5-Nov-2026 09:14:00 +0000").
pub fn format_imap_datetime(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = civil(unix);
    format!("{d:>2}-{}-{y:04} {h:02}:{mi:02}:{s:02} +0000", MONTHS[mo as usize - 1])
}

/// A non-empty run of ASCII digits as a number (no sign, no spaces).
fn digits(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn month(s: &str) -> Option<u32> {
    MONTHS.iter().position(|m| m.eq_ignore_ascii_case(s)).map(|i| i as u32 + 1)
}

/// Day number of a valid (day, month name, 4-digit year), else None.
fn date_days(day: u32, mon: &str, year: &str) -> Option<i64> {
    let m = month(mon)?;
    if year.len() != 4 {
        return None;
    }
    let y = i64::from(digits(year)?);
    (day >= 1 && day <= days_in_month(y, m)).then(|| days_from_civil(y, m, day))
}

/// Parse RFC 3501 `date-time` (no DQUOTEs; day " 5" or "05"; month case-insensitive;
/// zone +hhmm/-hhmm applied). None on any invalid field or trailing input.
pub fn parse_imap_datetime(s: &str) -> Option<i64> {
    // "dd-Mon-yyyy hh:mm:ss +hhmm": 26 ASCII bytes with fixed separators.
    let b = s.as_bytes();
    if b.len() != 26 || !s.is_ascii() {
        return None;
    }
    if b[2] != b'-' || b[6] != b'-' || b[11] != b' ' || b[14] != b':' || b[17] != b':' || b[20] != b' ' {
        return None;
    }
    let day = match &s[0..2] {
        d if d.starts_with(' ') => digits(&d[1..])?,
        d => digits(d)?,
    };
    let days = date_days(day, &s[3..6], &s[7..11])?;
    let (h, mi, sec) = (digits(&s[12..14])?, digits(&s[15..17])?, digits(&s[18..20])?);
    if h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let sign = match b[21] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let (zh, zm) = (digits(&s[22..24])?, digits(&s[24..26])?);
    if zh > 23 || zm > 59 {
        return None;
    }
    let local = days * DAY + i64::from(h * 3600 + mi * 60 + sec);
    Some(local - sign * i64::from(zh * 3600 + zm * 60))
}

/// Parse RFC 3501 `date-text` ("1-Feb-1994", "01-feb-1994") used by SEARCH BEFORE/ON/SINCE.
/// Returns 00:00:00 UTC of that day. None for impossible dates (31-Apr, 29-Feb-2025).
pub fn parse_imap_date(s: &str) -> Option<i64> {
    let mut parts = s.split('-');
    let (d, m, y) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || d.len() > 2 {
        return None;
    }
    Some(date_days(digits(d)?, m, y)? * DAY)
}

/// 00:00:00 UTC of the day containing `unix` (SEARCH compares dates, ignoring time).
pub fn imap_day(unix: i64) -> i64 {
    unix.div_euclid(DAY) * DAY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip_over_four_centuries() {
        for z in (-200_000..200_000).step_by(37) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
    }

    #[test]
    fn helpers_format_utc() {
        assert_eq!(format_rfc3339(1_793_870_040), "2026-11-05T09:14:00Z");
        assert_eq!(yyyymm(1_773_576_000), "202603");
        assert_eq!(format_http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}
