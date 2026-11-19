//! A parser for the block-style YAML the workflows are written in, for the tests that read
//! them (`workflows_tuf.rs`, `workflows_publishers.rs`); a YAML parser is not a dependency of
//! `xtask`. It fails on what it does not understand (flow mappings other than `{}`, anchors,
//! tags, continuation lines), so a workflow written so that a test cannot read it fails the
//! test instead of passing it.

#![allow(dead_code)]

use serde_json::{Map, Value};

struct Parser {
    lines: Vec<String>,
    i: usize,
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

impl Parser {
    fn blank(line: &str) -> bool {
        let t = line.trim();
        t.is_empty() || t.starts_with('#')
    }

    /// The next line with content: its indentation and text.
    fn peek(&mut self) -> Result<Option<(usize, String)>, String> {
        while self.i < self.lines.len() && Parser::blank(&self.lines[self.i]) {
            self.i += 1;
        }
        let Some(line) = self.lines.get(self.i) else {
            return Ok(None);
        };
        if line.trim_start_matches(' ').starts_with('\t') {
            return Err(format!("line {}: a tab in the indentation", self.i + 1));
        }
        Ok(Some((indent_of(line), line.trim().to_owned())))
    }

    fn block(&mut self, indent: usize) -> Result<Value, String> {
        let Some((n, text)) = self.peek()? else {
            return Ok(Value::Null);
        };
        if n != indent {
            return Err(format!("line {}: unexpected indentation", self.i + 1));
        }
        if text == "-" || text.starts_with("- ") {
            self.sequence(indent)
        } else if split_key(&text)?.is_some() {
            self.mapping(indent)
        } else {
            self.i += 1;
            scalar(&text)
        }
    }

    fn sequence(&mut self, n: usize) -> Result<Value, String> {
        let mut items = Vec::new();
        while let Some((ind, text)) = self.peek()? {
            if ind != n || !(text == "-" || text.starts_with("- ")) {
                break;
            }
            let rest = text[1..].trim_start();
            if rest.is_empty() {
                self.i += 1;
                items.push(match self.peek()? {
                    Some((next, _)) if next > n => self.block(next)?,
                    _ => Value::Null,
                });
            } else {
                // The item's first line is the rest of this one, further in.
                let at = n + (text.len() - rest.len());
                self.lines[self.i] = format!("{}{rest}", " ".repeat(at));
                items.push(self.block(at)?);
            }
        }
        Ok(Value::Array(items))
    }

    fn mapping(&mut self, n: usize) -> Result<Value, String> {
        let mut map = Map::new();
        while let Some((ind, text)) = self.peek()? {
            if ind < n || (ind == n && (text == "-" || text.starts_with("- "))) {
                break;
            }
            if ind > n {
                return Err(format!(
                    "line {}: unexpected indentation (a continued scalar?)",
                    self.i + 1
                ));
            }
            let Some((key, rest)) = split_key(&text)? else {
                return Err(format!("line {}: not a `key: value` line", self.i + 1));
            };
            self.i += 1;
            let value = if rest.is_empty() {
                match self.peek()? {
                    Some((next, _)) if next > n => self.block(next)?,
                    Some((next, text)) if next == n && (text == "-" || text.starts_with("- ")) => {
                        self.sequence(n)?
                    }
                    _ => Value::Null,
                }
            } else if rest.starts_with('|') || rest.starts_with('>') {
                self.block_scalar(n, &rest)?
            } else {
                scalar(&rest)?
            };
            if map.insert(key.clone(), value).is_some() {
                return Err(format!("the key {key:?} is twice in a mapping"));
            }
        }
        Ok(Value::Object(map))
    }

    fn block_scalar(&mut self, n: usize, header: &str) -> Result<Value, String> {
        let folded = header.starts_with('>');
        let mut body: Vec<String> = Vec::new();
        while let Some(line) = self.lines.get(self.i) {
            if !line.trim().is_empty() && indent_of(line) <= n {
                break;
            }
            body.push(line.clone());
            self.i += 1;
        }
        let strip = body
            .iter()
            .filter(|l| !l.trim().is_empty())
            .map(|l| indent_of(l))
            .min()
            .unwrap_or(0);
        let lines: Vec<&str> = body
            .iter()
            .map(|l| {
                if l.len() >= strip {
                    l[strip..].trim_end()
                } else {
                    ""
                }
            })
            .collect();
        let mut text = if folded {
            let mut out = String::new();
            for (k, line) in lines.iter().enumerate() {
                if k > 0 {
                    let blank = line.is_empty() || lines[k - 1].is_empty();
                    out.push(if blank { '\n' } else { ' ' });
                    if line.is_empty() && lines[k - 1].is_empty() {
                        continue;
                    }
                }
                out.push_str(line);
            }
            out
        } else {
            lines.join("\n")
        };
        text = text.trim_end_matches('\n').to_owned();
        if !header.contains('-') {
            text.push('\n');
        }
        Ok(Value::String(text))
    }
}

/// `key: rest` of a mapping line, or `None` if the line is not one.
fn split_key(text: &str) -> Result<Option<(String, String)>, String> {
    if let Some(quoted) = text.strip_prefix('"') {
        let Some(end) = quoted.find('"') else {
            return Err(format!("an unterminated key in {text:?}"));
        };
        let rest = quoted[end + 1..].strip_prefix(':').map(str::trim);
        return Ok(rest.map(|r| (quoted[..end].to_owned(), r.to_owned())));
    }
    let at = if text.ends_with(':') && !text[..text.len() - 1].contains(": ") {
        Some(text.len() - 1)
    } else {
        text.find(": ")
    };
    Ok(at.map(|at| {
        (
            text[..at].trim().to_owned(),
            text[at + 1..].trim().to_owned(),
        )
    }))
}

/// A one-line value, comments removed; what the parser does not read is an error.
fn scalar(text: &str) -> Result<Value, String> {
    let text = strip_comment(text);
    let text = text.trim();
    let Some(first) = text.chars().next() else {
        return Ok(Value::Null);
    };
    if text == "{}" {
        // `permissions: {}`, the one flow mapping the workflows use.
        return Ok(Value::Object(Map::new()));
    }
    match first {
        '"' => {
            let inner = text
                .strip_prefix('"')
                .and_then(|t| t.strip_suffix('"'))
                .ok_or_else(|| format!("a quoted scalar that does not end: {text:?}"))?;
            Ok(Value::String(
                inner
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
                    .replace("\\n", "\n"),
            ))
        }
        '\'' => {
            let inner = text
                .strip_prefix('\'')
                .and_then(|t| t.strip_suffix('\''))
                .ok_or_else(|| format!("a quoted scalar that does not end: {text:?}"))?;
            Ok(Value::String(inner.replace("''", "'")))
        }
        '[' => {
            let inner = text
                .strip_prefix('[')
                .and_then(|t| t.strip_suffix(']'))
                .ok_or_else(|| format!("a flow sequence that does not end: {text:?}"))?;
            if inner.contains(['[', '{']) {
                return Err(format!("a nested flow collection: {text:?}"));
            }
            let mut items = Vec::new();
            for item in inner.split(',').map(str::trim).filter(|i| !i.is_empty()) {
                items.push(scalar(item)?);
            }
            Ok(Value::Array(items))
        }
        '{' | '&' | '*' | '!' | '?' | '%' | '@' | '`' => {
            Err(format!("YAML this test does not read: {text:?}"))
        }
        _ => Ok(Value::String(text.to_owned())),
    }
}

fn strip_comment(text: &str) -> &str {
    let mut quote = None;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match (quote, b) {
            (None, b'"' | b'\'') => quote = Some(b),
            (Some(q), c) if c == q => quote = None,
            (None, b'#') if i == 0 || bytes[i - 1] == b' ' => return &text[..i],
            _ => {}
        }
    }
    text
}

pub fn parse_yaml(text: &str) -> Result<Value, String> {
    let mut parser = Parser {
        lines: text
            .lines()
            .map(|l| l.trim_end_matches('\r').to_owned())
            .collect(),
        i: 0,
    };
    if parser.peek()?.is_some_and(|(_, t)| t == "---") {
        return Err("a document marker".to_owned());
    }
    let value = parser.block(0)?;
    match parser.peek()? {
        None => Ok(value),
        Some(_) => Err(format!("line {}: text after the document", parser.i + 1)),
    }
}

/// Every string of `value` with its path.
pub fn leaves(value: &Value, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, String)>) {
    match value {
        Value::String(s) => out.push((path.clone(), s.clone())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                path.push(i.to_string());
                leaves(item, path, out);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                leaves(v, path, out);
                path.pop();
            }
        }
        _ => {}
    }
}

/// Whether the action `uses` is pinned to a commit (40 hex digits).
pub fn pinned(uses: &str) -> bool {
    uses.split('@')
        .nth(1)
        .and_then(|r| r.split_whitespace().next())
        .is_some_and(|r| r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()))
}
