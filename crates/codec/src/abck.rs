//! `_abck` parsing: verdict state, the edge state blob, and work items.

use crate::{CodecError, Result};

/// Which framing an `_abck` value uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// `<token>~<status>~<state>~<flags>~<work>~...`
    Legacy,
    /// `~<score>~<endpoint>~<flags>~<timestamp>~<nonce>~`
    Bmp,
}

/// Parsed verdict state (legacy framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Field 1 is `-1`: no accepted telemetry yet.
    Unvalidated,
    /// Field 1 is `0`.
    Validated,
    /// Any other numeric state.
    Other(i64),
    /// Field 1 was not numeric.
    Unknown,
}

/// One proof-of-work item carried in field 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkItem {
    pub id: String,
    pub salt: String,
    pub difficulty: u32,
    pub delay_ms: u64,
    pub slice_ms: u64,
    pub version: Option<u32>,
}

/// A parsed `_abck` value. Fields stay raw and ordered.
#[derive(Debug, Clone)]
pub struct Abck {
    pub raw: String,
    pub fields: Vec<String>,
    pub style: Style,
}

impl Abck {
    pub fn parse(raw: &str) -> Self {
        let style = if raw.starts_with('~') {
            Style::Bmp
        } else {
            Style::Legacy
        };
        Self {
            raw: raw.to_owned(),
            fields: raw.split('~').map(str::to_owned).collect(),
            style,
        }
    }

    /// Session token used as the proof-of-work prefix (legacy field 0).
    pub fn token(&self) -> &str {
        self.fields.first().map(String::as_str).unwrap_or_default()
    }

    /// Verdict state, from legacy field 1.
    pub fn state(&self) -> State {
        match self.style {
            Style::Bmp => State::Unknown,
            Style::Legacy => match self.fields.get(1).and_then(|v| v.parse::<i64>().ok()) {
                Some(-1) => State::Unvalidated,
                Some(0) => State::Validated,
                Some(other) => State::Other(other),
                None => State::Unknown,
            },
        }
    }

    /// True when the cookie is not in the `~-1~` challenge state.
    pub fn looks_validated(&self) -> bool {
        !matches!(self.state(), State::Unvalidated)
    }

    /// The opaque edge state blob (legacy field 2). It grows as posts land.
    pub fn state_blob(&self) -> Option<&str> {
        match self.style {
            Style::Legacy => self.fields.get(2).map(String::as_str),
            Style::Bmp => self.fields.get(1).map(String::as_str),
        }
    }

    pub fn state_blob_len(&self) -> Option<usize> {
        self.state_blob().map(str::len)
    }

    /// Work items from legacy field 4, `-1` meaning "none".
    pub fn work_items(&self) -> Result<Vec<WorkItem>> {
        let raw = match self.style {
            Style::Legacy => self.fields.get(4).map(String::as_str).unwrap_or("-1"),
            Style::Bmp => return Ok(Vec::new()),
        };
        if raw.is_empty() || raw == "-1" {
            return Ok(Vec::new());
        }
        raw.split("||").map(parse_work_item).collect()
    }
}

fn parse_work_item(raw: &str) -> Result<WorkItem> {
    let parts: Vec<&str> = raw.split('-').collect();
    if parts.len() < 5 {
        return Err(CodecError::Format(format!("work item {raw:?}")));
    }
    let number = |index: usize, what: &str| -> Result<u64> {
        parts[index]
            .parse()
            .map_err(|_| CodecError::Format(format!("{what} in {raw:?}")))
    };
    Ok(WorkItem {
        id: parts[0].to_owned(),
        salt: parts[1].to_owned(),
        difficulty: u32::try_from(number(2, "difficulty")?)
            .map_err(|_| CodecError::Format("difficulty range".to_owned()))?,
        delay_ms: number(3, "delay")?,
        slice_ms: number(4, "slice")?,
        version: parts.get(5).and_then(|v| v.parse().ok()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unvalidated_and_blob_growth() {
        let before = Abck::parse("ABCD~-1~YAAQblob~-1~-1~-1");
        assert_eq!(before.state(), State::Unvalidated);
        assert_eq!(before.state_blob_len(), Some(8));

        let after = Abck::parse("ABCD~0~YAAQblobYAAQblob~-1~-1~-1");
        assert_eq!(after.state(), State::Validated);
        assert!(after.looks_validated());
        assert_eq!(after.state_blob_len(), Some(16));
    }

    #[test]
    fn work_items_parse() {
        let abck = Abck::parse("TOKEN~-1~blob~0~abcd-salt-450-0-1000-2~-1");
        let items = abck.work_items().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].difficulty, 450);
        assert_eq!(items[0].version, Some(2));
        assert_eq!(items[0].slice_ms, 1000);
    }

    #[test]
    fn no_work_is_not_an_error() {
        let items = Abck::parse("T~-1~b~0~-1~-1").work_items().expect("items");
        assert!(items.is_empty());
    }

    #[test]
    fn bmp_framing_is_recognized() {
        let value = Abck::parse("~42~/path~0~1700000000~nonce~");
        assert_eq!(value.style, Style::Bmp);
        assert_eq!(value.state_blob(), Some("42"));
    }
}
