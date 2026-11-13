//! Literal scanning for the supported bmak table shapes; no JavaScript execution.

use native_payload::template::parse_js_string_array;

/// Yield flat string-literal arrays, regardless of the assigned variable's
/// name, quoting style or surrounding wrapper. Comments and quoted source
/// text are skipped; no JavaScript is evaluated.
pub(super) fn string_arrays(source: &str) -> impl Iterator<Item = Vec<String>> + '_ {
    let bytes = source.as_bytes();
    let mut index = 0;
    let mut regex_allowed = true;
    let mut control_paren = false;
    let mut parens = Vec::new();
    std::iter::from_fn(move || {
        while index < bytes.len() {
            match (bytes[index], bytes.get(index + 1).copied()) {
                (b'\'' | b'"' | b'`', _) => {
                    index = quoted_end(bytes, index).unwrap_or(bytes.len());
                    regex_allowed = false;
                }
                (b'/', Some(b'/')) => {
                    index += 2;
                    while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                        index += 1;
                    }
                }
                (b'/', Some(b'*')) => {
                    index += 2;
                    while index + 1 < bytes.len() && &bytes[index..index + 2] != b"*/" {
                        index += 1;
                    }
                    index = (index + 2).min(bytes.len());
                }
                (b'[', _) => {
                    let start = index;
                    index += 1;
                    if regex_allowed && let Some(end) = string_array_end(bytes, start) {
                        index = end;
                        regex_allowed = false;
                        if let Ok(array) = parse_js_string_array(&source[start..end]) {
                            return Some(array);
                        }
                    }
                    regex_allowed = true;
                }
                (b'/', _) if regex_allowed => {
                    if let Some(end) = regex_end(bytes, index) {
                        index = end;
                        regex_allowed = false;
                    } else {
                        index = bytes.len();
                    }
                }
                (b'(', _) => {
                    parens.push(control_paren);
                    control_paren = false;
                    regex_allowed = true;
                    index += 1;
                }
                (b')', _) => {
                    regex_allowed = parens.pop().unwrap_or(false);
                    index += 1;
                }
                (b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$', _) => {
                    let start = index;
                    while bytes
                        .get(index)
                        .is_some_and(|ch| ch.is_ascii_alphanumeric() || matches!(ch, b'_' | b'$'))
                    {
                        index += 1;
                    }
                    regex_allowed = matches!(
                        &bytes[start..index],
                        b"return"
                            | b"throw"
                            | b"case"
                            | b"delete"
                            | b"void"
                            | b"typeof"
                            | b"in"
                            | b"instanceof"
                            | b"yield"
                            | b"await"
                            | b"else"
                            | b"do"
                    );
                    control_paren = matches!(
                        &bytes[start..index],
                        b"if" | b"while" | b"for" | b"with" | b"switch" | b"catch"
                    );
                }
                (ch, _) => {
                    if !ch.is_ascii_whitespace() {
                        regex_allowed = !matches!(ch, b']' | b'0'..=b'9' | b'.');
                        control_paren = false;
                    }
                    index += 1;
                }
            }
        }
        None
    })
}

fn regex_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    let mut character_class = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'[' => {
                character_class = true;
                index += 1;
            }
            b']' => {
                character_class = false;
                index += 1;
            }
            b'/' if !character_class => {
                index += 1;
                while bytes.get(index).is_some_and(u8::is_ascii_alphabetic) {
                    index += 1;
                }
                return Some(index);
            }
            b'\n' | b'\r' => return None,
            _ => index += 1,
        }
    }
    None
}

fn quoted_end(bytes: &[u8], start: usize) -> Option<usize> {
    let quote = bytes[start];
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            ch if ch == quote => return Some(index + 1),
            b'$' if quote == b'`' && bytes.get(index + 1) == Some(&b'{') => {
                index = template_expression_end(bytes, index + 2)?;
            }
            _ => index += 1,
        }
    }
    None
}

// Skip interpolations too: a nested template must not expose its text as code.
fn template_expression_end(bytes: &[u8], mut index: usize) -> Option<usize> {
    let mut depth = 1;
    let mut regex_allowed = true;
    while index < bytes.len() {
        match (bytes[index], bytes.get(index + 1).copied()) {
            (b'\'' | b'"' | b'`', _) => {
                index = quoted_end(bytes, index)?;
                regex_allowed = false;
            }
            (b'/', Some(b'/')) => {
                index += 2;
                while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                    index += 1;
                }
            }
            (b'/', Some(b'*')) => {
                index += 2;
                while index + 1 < bytes.len() && &bytes[index..index + 2] != b"*/" {
                    index += 1;
                }
                index = (index + 2).min(bytes.len());
            }
            (b'/', _) if regex_allowed => {
                index = regex_end(bytes, index)?;
                regex_allowed = false;
            }
            (b'{', _) => {
                depth += 1;
                index += 1;
                regex_allowed = true;
            }
            (b'}', _) => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return Some(index);
                }
                regex_allowed = true;
            }
            (ch, _) => {
                if !ch.is_ascii_whitespace() {
                    regex_allowed = !matches!(ch, b')' | b']' | b'0'..=b'9' | b'.' | b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$');
                }
                index += 1;
            }
        }
    }
    None
}

fn string_array_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start + 1;
    loop {
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        if !matches!(bytes.get(index), Some(b'\'' | b'"')) {
            return None;
        }
        index = quoted_end(bytes, index)?;
        while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
            index += 1;
        }
        match bytes.get(index) {
            Some(b']') => return Some(index + 1),
            Some(b',') => {
                index += 1;
                while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
                    index += 1;
                }
                if bytes.get(index) == Some(&b']') {
                    return Some(index + 1);
                }
            }
            _ => return None,
        }
    }
}
