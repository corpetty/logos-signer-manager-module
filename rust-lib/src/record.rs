//! Domain-separated records: what an `ed25519` identity key signs.
//!
//! A record is the dCBOR encoding of `[domain, {fields}]`, and the signature covers
//! `SHA-256(record)`. Apps sign these rather than bare digests (Muster's
//! `module/src/hashing/hash_input.nim` builds them), so the manager can show every field and
//! compute the digest itself: a `record` leg is never a digest the requester chose.
//!
//! The decoder accepts only the deterministic subset such records use:
//! - unsigned and negative integers, in their shortest form;
//! - byte strings, UTF-8 text, arrays, maps, `true`, `false`, `null`;
//! - definite lengths only;
//! - map keys strictly increasing in bytewise order of their encodings.
//!
//! Floats, tags, other simple values and indefinite lengths are refused, and a record is accepted
//! only if it re-encodes to the same bytes.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    /// CBOR major type 1: the value is `-1 - n`.
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecordError {
    #[error("non-canonical-record: {0}")]
    NonCanonical(&'static str),
    #[error("not-a-record: {0}")]
    NotARecord(&'static str),
}

type Result<T> = std::result::Result<T, RecordError>;

const MAX_DEPTH: usize = 32;

// ── encode ──────────────────────────────────────────────────────────────────

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// The deterministic encoding. Map entries are emitted in bytewise order of their encoded
/// keys whatever order they are held in.
pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Uint(u) => head(out, 0, *u),
        Value::Nint(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(out, 3, t.len() as u64);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for i in items {
                encode_into(i, out);
            }
        }
        Value::Map(pairs) => {
            let mut enc: Vec<(Vec<u8>, Vec<u8>)> =
                pairs.iter().map(|(k, v)| (encode(k), encode(v))).collect();
            enc.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, 5, enc.len() as u64);
            for (k, v) in enc {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

// ── strict decode ───────────────────────────────────────────────────────────

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.i.checked_add(n).ok_or(RecordError::NonCanonical("length overflow"))?;
        if end > self.b.len() {
            return Err(RecordError::NonCanonical("truncated"));
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }

    fn arg(&mut self, info: u8) -> Result<u64> {
        let v = match info {
            0..=23 => return Ok(info as u64),
            24 => self.take(1)?[0] as u64,
            25 => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            26 => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64,
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            31 => return Err(RecordError::NonCanonical("indefinite length")),
            _ => return Err(RecordError::NonCanonical("reserved additional info")),
        };
        let shortest = match info {
            24 => v >= 24,
            25 => v > 0xff,
            26 => v > 0xffff,
            _ => v > 0xffff_ffff,
        };
        if !shortest {
            return Err(RecordError::NonCanonical("integer not in shortest form"));
        }
        Ok(v)
    }

    fn len(&mut self, info: u8) -> Result<usize> {
        let n = self.arg(info)?;
        let n = usize::try_from(n).map_err(|_| RecordError::NonCanonical("length overflow"))?;
        if n > self.b.len() - self.i {
            // Every item is at least one byte; a longer count cannot be honest.
            return Err(RecordError::NonCanonical("truncated"));
        }
        Ok(n)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(RecordError::NonCanonical("nested too deeply"));
        }
        let ib = self.take(1)?[0];
        let (major, info) = (ib >> 5, ib & 0x1f);
        Ok(match major {
            0 => Value::Uint(self.arg(info)?),
            1 => Value::Nint(self.arg(info)?),
            2 => {
                let n = self.len(info)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            3 => {
                let n = self.len(info)?;
                let s = std::str::from_utf8(self.take(n)?)
                    .map_err(|_| RecordError::NonCanonical("text is not UTF-8"))?;
                Value::Text(s.to_string())
            }
            4 => {
                let n = self.len(info)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.value(depth + 1)?);
                }
                Value::Array(items)
            }
            5 => {
                let n = self.len(info)?;
                let mut pairs = Vec::with_capacity(n);
                let mut prev: Option<&[u8]> = None;
                for _ in 0..n {
                    let start = self.i;
                    let k = self.value(depth + 1)?;
                    let kb = &self.b[start..self.i];
                    if let Some(p) = prev {
                        if kb <= p {
                            return Err(RecordError::NonCanonical(
                                "map keys not in bytewise order, or duplicated",
                            ));
                        }
                    }
                    prev = Some(kb);
                    let v = self.value(depth + 1)?;
                    pairs.push((k, v));
                }
                Value::Map(pairs)
            }
            6 => return Err(RecordError::NonCanonical("tags are not allowed")),
            _ => match ib {
                0xf4 => Value::Bool(false),
                0xf5 => Value::Bool(true),
                0xf6 => Value::Null,
                0xf9..=0xfb => return Err(RecordError::NonCanonical("floats are not allowed")),
                0xff => return Err(RecordError::NonCanonical("indefinite length")),
                _ => return Err(RecordError::NonCanonical("simple value not allowed")),
            },
        })
    }
}

/// Decode one value, refusing any non-canonical encoding and any trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut r = Reader { b: bytes, i: 0 };
    let v = r.value(0)?;
    if r.i != bytes.len() {
        return Err(RecordError::NonCanonical("trailing bytes"));
    }
    // The checks above make this hold; the comparison is what the guarantee rests on.
    if encode(&v) != bytes {
        return Err(RecordError::NonCanonical("does not re-encode to the same bytes"));
    }
    Ok(v)
}

// ── records ─────────────────────────────────────────────────────────────────

/// A parsed `[domain, {fields}]` record and the exact bytes it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub domain: String,
    pub fields: Vec<(String, Value)>,
    bytes: Vec<u8>,
}

impl Record {
    /// Parse and check a record from its encoding.
    pub fn parse(bytes: &[u8]) -> Result<Record> {
        let v = decode(bytes)?;
        let Value::Array(items) = v else {
            return Err(RecordError::NotARecord("not an array"));
        };
        let [Value::Text(domain), Value::Map(pairs)] = items.as_slice() else {
            return Err(RecordError::NotARecord("not [domain, {fields}]"));
        };
        if domain.is_empty() {
            return Err(RecordError::NotARecord("empty domain"));
        }
        let mut fields = Vec::with_capacity(pairs.len());
        for (k, v) in pairs {
            let Value::Text(k) = k else {
                return Err(RecordError::NotARecord("a field name is not text"));
            };
            fields.push((k.clone(), v.clone()));
        }
        Ok(Record { domain: domain.clone(), fields, bytes: bytes.to_vec() })
    }

    /// Build a record this module authors itself (possession proofs, contexts, key refs).
    pub fn build(domain: &str, fields: Vec<(&str, Value)>) -> Record {
        let pairs = fields
            .iter()
            .map(|(k, v)| (Value::Text(k.to_string()), v.clone()))
            .collect();
        let bytes = encode(&Value::Array(vec![Value::Text(domain.into()), Value::Map(pairs)]));
        Record::parse(&bytes).expect("an encoded record parses")
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// What is signed: SHA-256 over the record's bytes.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.bytes).into()
    }

    /// One line per field, in the order the record holds them, for `render_lines`.
    pub fn render(&self) -> Vec<String> {
        let mut out = vec![format!("Domain: {}", escape(&self.domain))];
        for (k, v) in &self.fields {
            out.push(format!("  {}: {}", escape(k), diag(v)));
        }
        out
    }
}

/// CBOR diagnostic notation, with text escaped for display.
pub fn diag(v: &Value) -> String {
    match v {
        Value::Uint(u) => u.to_string(),
        Value::Nint(n) => format!("-{}", *n as u128 + 1),
        Value::Bytes(b) => format!("h'{}'", hex::encode(b)),
        Value::Text(t) => format!("\"{}\"", escape(t)),
        Value::Array(items) => {
            format!("[{}]", items.iter().map(diag).collect::<Vec<_>>().join(", "))
        }
        Value::Map(pairs) => format!(
            "{{{}}}",
            pairs
                .iter()
                .map(|(k, v)| format!("{}: {}", diag(k), diag(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".into(),
    }
}

/// Make text safe to show verbatim: control, bidi and zero-width characters become `\u{…}`
/// escapes, so what an approver displays cannot reorder or hide what is signed.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let hidden = c.is_control()
            || matches!(c as u32,
                0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2069 | 0xFEFF | 0x061C);
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ if hidden => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            _ => out.push(c),
        }
    }
    out
}

pub fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(domain: &str, fields: Vec<(&str, Value)>) -> Vec<u8> {
        Record::build(domain, fields).bytes().to_vec()
    }

    #[test]
    fn a_record_round_trips_and_hashes_its_own_bytes() {
        let b = rec("muster.event.author.v1", vec![("room", text("r")), ("n", Value::Uint(500))]);
        let r = Record::parse(&b).unwrap();
        assert_eq!(r.domain, "muster.event.author.v1");
        assert_eq!(r.digest(), <[u8; 32]>::from(Sha256::digest(&b)));
    }

    #[test]
    fn map_keys_are_ordered_bytewise_never_length_first() {
        // "b" (0x61 0x62) sorts before "aa" (0x62 0x61 0x61) bytewise, since the length
        // byte comes first in the encoding: shorter keys first, as CDE and Muster have it.
        let b = rec("d", vec![("aa", Value::Uint(1)), ("b", Value::Uint(2))]);
        let r = Record::parse(&b).unwrap();
        assert_eq!(r.fields[0].0, "b");
        // Swap the two entries by hand: refused.
        let mut swapped = vec![0x82, 0x61, b'd', 0xa2];
        swapped.extend([0x62, b'a', b'a', 0x01, 0x61, b'b', 0x02]);
        assert!(matches!(Record::parse(&swapped), Err(RecordError::NonCanonical(_))));
    }

    #[test]
    fn non_canonical_encodings_are_refused() {
        let cases: &[(&[u8], &str)] = &[
            (&[0x18, 0x05], "a small int in a long form"),
            (&[0x19, 0x00, 0xff], "a one-byte int in two"),
            (&[0x9f, 0x01, 0xff], "an indefinite array"),
            (&[0xfb, 0, 0, 0, 0, 0, 0, 0, 0], "a float"),
            (&[0xc1, 0x01], "a tag"),
            (&[0xf7], "undefined"),
            (&[0x01, 0x02], "trailing bytes"),
            (&[0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02], "a duplicated key"),
            (&[0x62, 0xff, 0xfe], "text that is not UTF-8"),
        ];
        for (bytes, what) in cases {
            assert!(decode(bytes).is_err(), "accepted {what}");
        }
    }

    #[test]
    fn a_bare_digest_is_not_a_record() {
        // 32 bytes of a transaction hash, as bytes or as raw data: never a record.
        let digest = [0xabu8; 32];
        assert!(Record::parse(&digest).is_err());
        let as_bstr = encode(&Value::Bytes(digest.to_vec()));
        assert!(matches!(Record::parse(&as_bstr), Err(RecordError::NotARecord(_))));
    }

    #[test]
    fn negative_ints_render_as_numbers() {
        assert_eq!(diag(&Value::Nint(0)), "-1");
        assert_eq!(diag(&Value::Nint(u64::MAX)), "-18446744073709551616");
    }

    #[test]
    fn hidden_characters_are_escaped_for_display() {
        assert_eq!(escape("pay\u{202E}evil"), "pay\\u{202e}evil");
        assert_eq!(escape("a\nb"), "a\\u{a}b");
    }
}
