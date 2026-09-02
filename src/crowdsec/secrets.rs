/*
    Copyright 2026 SOLTECSIS SOLUCIONES TECNOLOGICAS, SLU
    https://soltecsis.com
    info@soltecsis.com


    This file is part of FWCloud (https://fwcloud.net).

    FWCloud is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    FWCloud is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with FWCloud.  If not, see <https://www.gnu.org/licenses/>.
*/

pub const REDACTED_VALUE: &str = "[REDACTED]";

pub fn redact_sensitive_text(value: &str) -> String {
    value
        .lines()
        .map(redact_sensitive_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_sensitive_line(line: &str) -> String {
    let (key, value, separator) = if let Some((key, value)) = line.split_once(':') {
        (key, value, ':')
    } else if let Some((key, value)) = line.split_once('=') {
        (key, value, '=')
    } else {
        return line.to_string();
    };

    let normalized_key = key
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
        .replace(['_', '-'], "");
    if !matches!(
        normalized_key.as_str(),
        "apikey" | "bouncerapikey" | "enrollmentkey"
    ) {
        return line.to_string();
    }

    let trailing_whitespace = value
        .chars()
        .rev()
        .take_while(|character| character.is_whitespace())
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();

    format!("{key}{separator} {REDACTED_VALUE}{trailing_whitespace}")
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_text;

    #[test]
    fn redacts_remote_machine_bouncer_api_keys() {
        assert_eq!(
            redact_sensitive_text("bouncer_api_key: remote-secret"),
            "bouncer_api_key: [REDACTED]"
        );
    }
}
