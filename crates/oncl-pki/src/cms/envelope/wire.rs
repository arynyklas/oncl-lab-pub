//! BER framing for streamed envelopes: a pull parser over `Read` that never holds more than
//! a bounded buffer, and the length helpers of the writer.
//!
//! The parser only understands the framing (identifier, length, indefinite lengths,
//! constructed nesting). Small structures are captured raw with [`Parser::raw_element`] and
//! decoded by the `der` crate after [`crate::ber::to_der`]; the encrypted content is handed
//! out in pieces by [`Parser::stream_octets`].

use super::EnvelopeError;
use std::io::{BufReader, ErrorKind, Read};

/// A captured structure (recipient info, algorithm identifier, ...) larger than this is
/// refused: such a structure is not an envelope header.
pub(super) const MAX_RAW: usize = 4 << 20;
/// Deepest nesting the parser follows.
const MAX_DEPTH: usize = 16;

pub(super) const SEQUENCE: u8 = 0x30;
pub(super) const SET: u8 = 0x31;
pub(super) const OCTET_STRING: u8 = 0x04;
pub(super) const CONTEXT_0_CONSTRUCTED: u8 = 0xA0;
pub(super) const CONTEXT_0_PRIMITIVE: u8 = 0x80;

/// An element header.
#[derive(Clone, Copy, Debug)]
pub(super) struct Header {
    /// The identifier octet.
    pub tag: u8,
    /// The content length; `None` for the indefinite form.
    pub len: Option<u64>,
}

impl Header {
    pub(super) fn constructed(self) -> bool {
        self.tag & 0x20 != 0
    }
}

pub(super) struct Parser<R: Read> {
    reader: BufReader<R>,
    /// Bytes consumed so far.
    pos: u64,
    /// One byte read ahead while looking for an end-of-contents marker.
    ahead: Option<u8>,
    /// Open constructed elements, innermost last: the end offset of a definite one.
    frames: Vec<Option<u64>>,
    /// The tightest end offset among the open definite elements.
    limit: Option<u64>,
    record: Option<Vec<u8>>,
    buffer: Vec<u8>,
}

impl<R: Read> Parser<R> {
    pub(super) fn new(reader: R, buffer_len: usize) -> Self {
        Parser {
            reader: BufReader::with_capacity(8 * 1024, reader),
            pos: 0,
            ahead: None,
            frames: Vec::new(),
            limit: None,
            record: None,
            buffer: vec![0; buffer_len],
        }
    }

    fn io(error: std::io::Error) -> EnvelopeError {
        if error.kind() == ErrorKind::UnexpectedEof {
            EnvelopeError::Truncated
        } else {
            EnvelopeError::Source(error.to_string())
        }
    }

    fn byte(&mut self) -> Result<u8, EnvelopeError> {
        let b = match self.ahead.take() {
            Some(b) => {
                // Counted when peeked; recorded now that it is consumed.
                self.record_bytes(&[b])?;
                b
            }
            None => {
                self.check_room()?;
                let mut b = [0u8; 1];
                self.fill(&mut b)?;
                b[0]
            }
        };
        Ok(b)
    }

    fn check_room(&self) -> Result<(), EnvelopeError> {
        if self.limit.is_some_and(|end| self.pos >= end) {
            return Err(EnvelopeError::Malformed(
                "an element runs past the end of its container".into(),
            ));
        }
        Ok(())
    }

    fn record_bytes(&mut self, bytes: &[u8]) -> Result<(), EnvelopeError> {
        if let Some(rec) = &mut self.record {
            if rec.len() + bytes.len() > MAX_RAW {
                return Err(EnvelopeError::Malformed(
                    "a header structure is larger than the supported limit".into(),
                ));
            }
            rec.extend_from_slice(bytes);
        }
        Ok(())
    }

    /// Reads exactly `buf` from the source, counting and recording it.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), EnvelopeError> {
        self.reader.read_exact(buf).map_err(Self::io)?;
        self.pos += buf.len() as u64;
        self.record_bytes(buf)
    }

    /// Reads one element header.
    pub(super) fn header(&mut self) -> Result<Header, EnvelopeError> {
        let tag = self.byte()?;
        if tag & 0x1F == 0x1F {
            return Err(EnvelopeError::Malformed(
                "a high-tag-number identifier is not part of an envelope".into(),
            ));
        }
        let first = self.byte()?;
        let len = if first < 0x80 {
            Some(u64::from(first))
        } else if first == 0x80 {
            if tag & 0x20 == 0 {
                return Err(EnvelopeError::Malformed(
                    "indefinite length on a primitive element".into(),
                ));
            }
            None
        } else {
            let count = usize::from(first & 0x7F);
            if count > 8 {
                return Err(EnvelopeError::Malformed("length of length over 8".into()));
            }
            let mut value = 0u64;
            for _ in 0..count {
                value = (value << 8) | u64::from(self.byte()?);
            }
            Some(value)
        };
        if let Some(len) = len {
            let end = self
                .pos
                .checked_add(len)
                .ok_or_else(|| EnvelopeError::Malformed("length overflow".into()))?;
            if self.limit.is_some_and(|limit| end > limit) {
                return Err(EnvelopeError::Malformed(
                    "an element is longer than its container".into(),
                ));
            }
        }
        Ok(Header { tag, len })
    }

    /// Enters a constructed element.
    pub(super) fn enter(&mut self, header: Header) -> Result<(), EnvelopeError> {
        if !header.constructed() {
            return Err(EnvelopeError::Malformed(
                "a primitive element where a constructed one is required".into(),
            ));
        }
        if self.frames.len() >= MAX_DEPTH {
            return Err(EnvelopeError::Malformed("elements nested too deep".into()));
        }
        let end = header.len.map(|len| self.pos + len);
        self.frames.push(end);
        if let Some(end) = end {
            self.limit = Some(self.limit.map_or(end, |limit| limit.min(end)));
        }
        Ok(())
    }

    fn recompute_limit(&mut self) {
        self.limit = self.frames.iter().flatten().copied().min();
    }

    /// Whether the innermost open element has no more content (an indefinite one: its
    /// end-of-contents marker is next, and is left unread).
    pub(super) fn at_end(&mut self) -> Result<bool, EnvelopeError> {
        match self.frames.last().copied() {
            None => Err(EnvelopeError::Malformed("no open element".into())),
            Some(Some(end)) => Ok(self.pos >= end),
            Some(None) => {
                if self.ahead == Some(0) {
                    return Ok(true);
                }
                if self.ahead.is_some() {
                    return Ok(false);
                }
                self.check_room()?;
                let mut first = [0u8; 1];
                self.reader.read_exact(&mut first).map_err(Self::io)?;
                self.pos += 1;
                let first = first[0];
                self.ahead = Some(first);
                Ok(first == 0)
            }
        }
    }

    /// Leaves the innermost element, which must be at its end.
    pub(super) fn leave(&mut self) -> Result<(), EnvelopeError> {
        if !self.at_end()? {
            return Err(EnvelopeError::Malformed(
                "unexpected content at the end of an element".into(),
            ));
        }
        let frame = self.frames.pop().expect("at_end saw an open element");
        if frame.is_none() {
            // The end-of-contents marker is `00 00`.
            let first = self.byte()?;
            let second = self.byte()?;
            if first != 0 || second != 0 {
                return Err(EnvelopeError::Malformed(
                    "bad end-of-contents marker".into(),
                ));
            }
        }
        self.recompute_limit();
        Ok(())
    }

    /// The next element header inside the innermost element, or `None` at its end.
    pub(super) fn next(&mut self) -> Result<Option<Header>, EnvelopeError> {
        if self.at_end()? {
            return Ok(None);
        }
        self.header().map(Some)
    }

    /// Skips the content of an element whose header was just read.
    pub(super) fn skip(&mut self, header: Header) -> Result<(), EnvelopeError> {
        if header.constructed() {
            self.enter(header)?;
            while let Some(child) = self.next()? {
                self.skip(child)?;
            }
            return self.leave();
        }
        let mut left = header.len.unwrap_or(0);
        let mut scratch = [0u8; 4096];
        while left > 0 {
            let take = usize::try_from(left.min(scratch.len() as u64)).expect("at most 4096");
            self.fill(&mut scratch[..take])?;
            left -= take as u64;
        }
        Ok(())
    }

    /// The next element of the innermost element, whole, as received (BER).
    pub(super) fn raw_element(&mut self) -> Result<Vec<u8>, EnvelopeError> {
        if self.record.is_some() {
            return Err(EnvelopeError::Malformed("nested capture".into()));
        }
        self.record = Some(Vec::new());
        let result = self.capture();
        let record = self.record.take().expect("recording");
        result.map(|()| record)
    }

    fn capture(&mut self) -> Result<(), EnvelopeError> {
        if self.at_end()? {
            return Err(EnvelopeError::Malformed("an element is missing".into()));
        }
        let header = self.header()?;
        self.skip(header)
    }

    /// Streams the octets of the encrypted content, which `header` begins: a primitive or
    /// constructed (nested) OCTET STRING. Returns the number of octets.
    pub(super) fn stream_octets(
        &mut self,
        header: Header,
        sink: &mut dyn FnMut(&[u8]) -> Result<(), EnvelopeError>,
    ) -> Result<u64, EnvelopeError> {
        let mut buffer = std::mem::take(&mut self.buffer);
        let result = self.octets(header, &mut buffer, sink);
        self.buffer = buffer;
        result
    }

    fn octets(
        &mut self,
        header: Header,
        buffer: &mut [u8],
        sink: &mut dyn FnMut(&[u8]) -> Result<(), EnvelopeError>,
    ) -> Result<u64, EnvelopeError> {
        if !header.constructed() {
            let mut left = header.len.unwrap_or(0);
            let total = left;
            while left > 0 {
                let take = usize::try_from(left.min(buffer.len() as u64)).expect("buffer sized");
                self.fill(&mut buffer[..take])?;
                sink(&buffer[..take])?;
                left -= take as u64;
            }
            return Ok(total);
        }
        self.enter(header)?;
        let mut total = 0u64;
        while let Some(child) = self.next()? {
            if child.tag != OCTET_STRING && child.tag != OCTET_STRING | 0x20 {
                return Err(EnvelopeError::Malformed(
                    "the encrypted content is not made of OCTET STRING segments".into(),
                ));
            }
            total += self.octets(child, buffer, sink)?;
        }
        self.leave()?;
        Ok(total)
    }

    /// Whether the source has no more bytes.
    pub(super) fn at_eof(&mut self) -> Result<bool, EnvelopeError> {
        if self.ahead.is_some() {
            return Ok(false);
        }
        let mut b = [0u8; 1];
        match self.reader.read(&mut b) {
            Ok(0) => Ok(true),
            Ok(_) => Ok(false),
            Err(e) => Err(Self::io(e)),
        }
    }
}

/// DER/BER length octets of `len`.
pub(super) fn length(len: u64) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = vec![0x80 | (8 - skip) as u8];
    out.extend_from_slice(&bytes[skip..]);
    out
}

/// Octets a header with `len` content octets takes.
pub(super) fn header_len(len: u64) -> u64 {
    1 + length(len).len() as u64
}

/// The header of an element: definite when `len` is known, else the indefinite form.
pub(super) fn header(tag: u8, len: Option<u64>) -> Vec<u8> {
    let mut out = vec![tag];
    match len {
        Some(len) => out.extend_from_slice(&length(len)),
        None => out.push(0x80),
    }
    out
}

/// A definite element with the given content.
pub(super) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = header(tag, Some(content.len() as u64));
    out.extend_from_slice(content);
    out
}
