//! RFC 8785 JSON Canonicalization Scheme over `serde_json::Value`.
//!
//! `serde_jcs` cannot serialise numbers when `serde_json`'s
//! `arbitrary_precision` feature is enabled (it is, transitively), and
//! governance records carry numeric metrics, so this canonicaliser formats
//! numbers itself using the ECMAScript number-to-string rules.

use serde_json::Value;

/// Canonicalise `value` to its RFC 8785 string form.
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(
    value: &Value,
    out: &mut String,
) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b {
            "true"
        } else {
            "false"
        }),
        Value::Number(n) => out.push_str(&number_to_string(n)),
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| {
                a.0.encode_utf16()
                    .cmp(b.0.encode_utf16())
            });
            out.push('{');
            for (i, (k, v)) in entries
                .into_iter()
                .enumerate()
            {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_value(v, out);
            }
            out.push('}');
        }
    }
}

fn write_string(
    s: &str,
    out: &mut String,
) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn number_to_string(n: &serde_json::Number) -> String {
    if n.is_i64() || n.is_u64() {
        let f = n.as_f64().unwrap_or(0.0);
        if f.abs() < 9_007_199_254_740_992.0 {
            return n.to_string();
        }
        return es6_number(f);
    }
    es6_number(n.as_f64().unwrap_or(0.0))
}

fn es6_number(x: f64) -> String {
    if x == 0.0 {
        return "0".to_string();
    }
    let sign = if x < 0.0 { "-" } else { "" };
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci
        .split_once('e')
        .unwrap_or((sci.as_str(), "0"));
    let digits: String = mantissa
        .chars()
        .filter(|c| *c != '.')
        .collect();
    let k = digits.len() as i32;
    let n = exp
        .parse::<i32>()
        .unwrap_or(0)
        + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let exp_sign = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{digits}e{exp_sign}{}", e.abs())
        } else {
            format!("{}.{}e{exp_sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_and_strips_whitespace() {
        assert_eq!(canonicalize(&json!({"b": 1, "a": [true, null, "x"]})), r#"{"a":[true,null,"x"],"b":1}"#);
    }

    #[test]
    fn rfc8785_number_formatting() {
        let cases = [
            (1.0, "1"),
            (0.5, "0.5"),
            (0.001, "0.001"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (123456789012345680000.0, "123456789012345680000"),
            (4.5e-6, "0.0000045"),
            (-2.5, "-2.5"),
            (1.2345e25, "1.2345e+25"),
        ];
        for (x, want) in cases {
            assert_eq!(es6_number(x), want, "{x}");
        }
    }

    #[test]
    fn integers_and_escapes() {
        assert_eq!(canonicalize(&json!({"n": 42, "s": "a\"b\n\u{1}é"})), "{\"n\":42,\"s\":\"a\\\"b\\n\\u0001é\"}");
    }

    #[test]
    fn keys_sort_by_utf16_code_units() {
        assert_eq!(canonicalize(&json!({"\u{e000}": 1, "\u{10000}": 2})), "{\"\u{10000}\":2,\"\u{e000}\":1}");
    }
}
