//! Bounded, versioned S1 framing for an already authenticated TLS 1.3 stream.
//! Wire responses do not mint local consent, trusted peers or durable receipts.

use crate::identity::{KeyFingerprint, Sha256Digest, TransferId};
use crate::journal::{FileOffer, Receipt};
use crate::Error;
use std::io::{Read, Write};

pub const VERSION: u8 = 1;
pub const MAX_CONTROL: usize = 8 * 1024;
pub const MAX_CHUNK: usize = 64 * 1024;
pub const MAX_FILE: u64 = 64 * 1024 * 1024;

/// Guest recovery bytes travel only *inside* a freshly authenticated TLS
/// stream. Debug output deliberately never prints the bearer credential.
#[derive(Clone, PartialEq, Eq)]
pub struct WireRecoveryCredential([u8; 32]);

impl std::fmt::Debug for WireRecoveryCredential {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_str("WireRecoveryCredential([REDACTED])")
    }
}

impl WireRecoveryCredential {
    pub fn from_authenticated_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes == [0; 32] {
            return Err(Error::Unauthorized);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for WireRecoveryCredential {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

// Header: [version: u8, kind: u8, length: u32 big-endian].
const DATA: u8 = 32;

/// Every variant remains untrusted until checked against the verified TLS
/// session, exact offer and local journal. Ready is not recipient consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    Offer(FileOffer),
    Ready(TransferId),
    Decline(TransferId),
    Cancel(TransferId),
    End(TransferId),
    Complete(Receipt),
    ReceiptQuery(FileOffer),
    Failure(TransferId),
    /// Sent only after bilateral SAS, independent exact-offer owner approval,
    /// and durable reservation/verifier persistence. Not a trust grant.
    GuestReady(TransferId, WireRecoveryCredential),
    /// Only meaningful on the restricted fresh exact-key receipt-only TLS
    /// reconnect. Never a request to stage, re-send or re-publish a file.
    GuestReceiptQuery(FileOffer, WireRecoveryCredential),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Control(Control),
    Data(Vec<u8>),
}

pub fn validate_offer(offer: &FileOffer) -> Result<(), Error> {
    offer.validate()?;
    if offer.bytes > MAX_FILE {
        return Err(Error::Invalid("S1 maximum file size"));
    }
    Ok(())
}

fn encode_offer(o: &FileOffer, out: &mut Vec<u8>) -> Result<(), Error> {
    validate_offer(o)?;
    out.extend_from_slice(o.id.as_str().as_bytes());
    out.extend_from_slice(o.peer.as_str().as_bytes());
    out.extend_from_slice(o.manifest.as_str().as_bytes());
    out.extend_from_slice(&o.bytes.to_be_bytes());
    out.extend_from_slice(o.sha256.as_str().as_bytes());
    let name = o.name.as_bytes();
    let len = u16::try_from(name.len()).map_err(|_| Error::Invalid("wire file name"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(name);
    Ok(())
}

fn encode_receipt(r: &Receipt, out: &mut Vec<u8>) -> Result<(), Error> {
    if r.bytes > MAX_FILE {
        return Err(Error::Invalid("S1 maximum file size"));
    }
    out.extend_from_slice(r.transfer_id.as_str().as_bytes());
    out.extend_from_slice(r.peer.as_str().as_bytes());
    out.extend_from_slice(r.manifest.as_str().as_bytes());
    out.extend_from_slice(&r.bytes.to_be_bytes());
    out.extend_from_slice(r.sha256.as_str().as_bytes());
    Ok(())
}

fn take<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    if src.len() < n {
        return Err(Error::Invalid("truncated wire value"));
    }
    let (a, b) = src.split_at(n);
    *src = b;
    Ok(a)
}

fn text<'a>(src: &mut &'a [u8], n: usize) -> Result<&'a str, Error> {
    std::str::from_utf8(take(src, n)?).map_err(|_| Error::Invalid("wire UTF-8"))
}

fn id(src: &mut &[u8]) -> Result<TransferId, Error> {
    TransferId::parse(text(src, 32)?)
}

fn size(src: &mut &[u8]) -> Result<u64, Error> {
    let bytes: [u8; 8] = take(src, 8)?
        .try_into()
        .map_err(|_| Error::Invalid("wire size"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_offer(src: &mut &[u8]) -> Result<FileOffer, Error> {
    let id = id(src)?;
    let peer = KeyFingerprint::parse(text(src, 64)?)?;
    let manifest = Sha256Digest::parse(text(src, 64)?)?;
    let bytes = size(src)?;
    let sha256 = Sha256Digest::parse(text(src, 64)?)?;
    let name_len_bytes: [u8; 2] = take(src, 2)?
        .try_into()
        .map_err(|_| Error::Invalid("wire file name"))?;
    let name_len = u16::from_be_bytes(name_len_bytes) as usize;
    if name_len > 255 {
        return Err(Error::Invalid("wire file name"));
    }
    let name = text(src, name_len)?.to_owned();
    let o = FileOffer {
        id,
        peer,
        manifest,
        name,
        bytes,
        sha256,
    };
    validate_offer(&o)?;
    Ok(o)
}

fn decode_receipt(src: &mut &[u8]) -> Result<Receipt, Error> {
    let r = Receipt {
        transfer_id: id(src)?,
        peer: KeyFingerprint::parse(text(src, 64)?)?,
        manifest: Sha256Digest::parse(text(src, 64)?)?,
        bytes: size(src)?,
        sha256: Sha256Digest::parse(text(src, 64)?)?,
    };
    if r.bytes > MAX_FILE {
        return Err(Error::Invalid("S1 maximum file size"));
    }
    Ok(r)
}

impl Frame {
    pub fn write_to(&self, out: &mut impl Write) -> Result<(), Error> {
        let mut payload = Vec::new();
        let kind = match self {
            Self::Data(bytes) => {
                if bytes.is_empty() || bytes.len() > MAX_CHUNK {
                    return Err(Error::Invalid("wire data bounds"));
                }
                payload.extend_from_slice(bytes);
                DATA
            }
            Self::Control(control) => match control {
                Control::Offer(o) => {
                    encode_offer(o, &mut payload)?;
                    1
                }
                Control::Ready(id) => {
                    payload.extend_from_slice(id.as_str().as_bytes());
                    2
                }
                Control::Decline(id) => {
                    payload.extend_from_slice(id.as_str().as_bytes());
                    3
                }
                Control::Cancel(id) => {
                    payload.extend_from_slice(id.as_str().as_bytes());
                    4
                }
                Control::End(id) => {
                    payload.extend_from_slice(id.as_str().as_bytes());
                    5
                }
                Control::Complete(r) => {
                    encode_receipt(r, &mut payload)?;
                    6
                }
                Control::ReceiptQuery(o) => {
                    encode_offer(o, &mut payload)?;
                    7
                }
                Control::Failure(id) => {
                    payload.extend_from_slice(id.as_str().as_bytes());
                    8
                }
                Control::GuestReady(id, token) => {
                    payload.extend_from_slice(id.as_str().as_bytes());
                    payload.extend_from_slice(token.as_bytes());
                    9
                }
                Control::GuestReceiptQuery(offer, token) => {
                    encode_offer(offer, &mut payload)?;
                    payload.extend_from_slice(token.as_bytes());
                    10
                }
            },
        };
        if payload.is_empty() || (kind != DATA && payload.len() > MAX_CONTROL) {
            return Err(Error::Invalid("wire control bounds"));
        }
        out.write_all(&[VERSION, kind])?;
        out.write_all(&(payload.len() as u32).to_be_bytes())?;
        out.write_all(&payload)?;
        Ok(())
    }

    pub fn read_from(input: &mut impl Read) -> Result<Self, Error> {
        let mut header = [0u8; 6];
        input.read_exact(&mut header)?;
        if header[0] != VERSION {
            return Err(Error::Invalid("wire version"));
        }
        let kind = header[1];
        if kind != DATA && !(1..=10).contains(&kind) {
            return Err(Error::Invalid("wire kind"));
        }
        let len = u32::from_be_bytes(header[2..].try_into().unwrap()) as usize;
        let max = if kind == DATA { MAX_CHUNK } else { MAX_CONTROL };
        if len == 0 || len > max {
            return Err(Error::Invalid("wire frame bounds"));
        }
        let mut bytes = vec![0; len];
        input.read_exact(&mut bytes)?;
        if kind == DATA {
            return Ok(Self::Data(bytes));
        }
        let mut src = bytes.as_slice();
        let control = match kind {
            1 => Control::Offer(decode_offer(&mut src)?),
            2 => Control::Ready(id(&mut src)?),
            3 => Control::Decline(id(&mut src)?),
            4 => Control::Cancel(id(&mut src)?),
            5 => Control::End(id(&mut src)?),
            6 => Control::Complete(decode_receipt(&mut src)?),
            7 => Control::ReceiptQuery(decode_offer(&mut src)?),
            8 => Control::Failure(id(&mut src)?),
            9 => Control::GuestReady(
                id(&mut src)?,
                WireRecoveryCredential::from_authenticated_bytes(
                    take(&mut src, 32)?
                        .try_into()
                        .map_err(|_| Error::Invalid("guest credential length"))?,
                )?,
            ),
            10 => Control::GuestReceiptQuery(
                decode_offer(&mut src)?,
                WireRecoveryCredential::from_authenticated_bytes(
                    take(&mut src, 32)?
                        .try_into()
                        .map_err(|_| Error::Invalid("guest credential length"))?,
                )?,
            ),
            _ => return Err(Error::Invalid("wire kind")),
        };
        if !src.is_empty() {
            return Err(Error::Invalid("wire trailing bytes"));
        }
        Ok(Self::Control(control))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn example() -> FileOffer {
        FileOffer {
            id: TransferId::parse(&"a".repeat(32)).unwrap(),
            peer: KeyFingerprint::parse(&"b".repeat(64)).unwrap(),
            manifest: Sha256Digest::parse(&"c".repeat(64)).unwrap(),
            name: "Report_日本語.pdf".into(),
            bytes: MAX_FILE,
            sha256: Sha256Digest::parse(&"d".repeat(64)).unwrap(),
        }
    }

    #[test]
    fn roundtrips_bounded_control_and_data() {
        for original in [
            Frame::Control(Control::Offer(example())),
            Frame::Control(Control::ReceiptQuery(example())),
            Frame::Control(Control::Cancel(example().id)),
            Frame::Data(vec![1, 2, 3]),
        ] {
            let mut stream = Vec::new();
            original.write_to(&mut stream).unwrap();
            assert_eq!(
                Frame::read_from(&mut Cursor::new(stream)).unwrap(),
                original
            );
        }
    }

    #[test]
    fn rejects_bad_versions_kinds_sizes_and_truncation() {
        for raw in [
            vec![VERSION + 1, DATA, 0, 0, 0, 1, 1],
            vec![VERSION, 250, 0, 0, 0, 1, 1],
            vec![VERSION, DATA, 0, 0, 0, 0],
            vec![VERSION, DATA, 0, 1, 0, 1],
            vec![VERSION, 1, 0, 0, 32, 1],
            vec![VERSION, DATA, 0, 0, 0, 5, 1],
        ] {
            assert!(Frame::read_from(&mut Cursor::new(raw)).is_err());
        }
    }

    #[test]
    fn rejects_untrusted_paths_oversize_and_trailing_bytes() {
        let mut unsafe_name = example();
        unsafe_name.name = "../file".into();
        assert!(Frame::Control(Control::Offer(unsafe_name))
            .write_to(&mut Vec::new())
            .is_err());
        let mut oversized = example();
        oversized.bytes += 1;
        assert!(Frame::Control(Control::Offer(oversized))
            .write_to(&mut Vec::new())
            .is_err());
        assert!(Frame::Data(vec![0; MAX_CHUNK + 1])
            .write_to(&mut Vec::new())
            .is_err());
        let mut stream = Vec::new();
        Frame::Control(Control::Offer(example()))
            .write_to(&mut stream)
            .unwrap();
        let len = u32::from_be_bytes(stream[2..6].try_into().unwrap()) + 1;
        stream[2..6].copy_from_slice(&len.to_be_bytes());
        stream.push(0);
        assert!(Frame::read_from(&mut Cursor::new(stream)).is_err());
    }

    #[test]
    fn refuses_malformed_wire_offer_and_invalid_utf8() {
        let mut canonical = Vec::new();
        Frame::Control(Control::Offer(example()))
            .write_to(&mut canonical)
            .unwrap();
        // Header + id + peer + manifest + u64 size + sha256 + u16 name len.
        const NAME_OFFSET: usize = 6 + 32 + 64 + 64 + 8 + 64 + 2;
        let mut traversal = canonical.clone();
        traversal[NAME_OFFSET] = b'/';
        assert!(Frame::read_from(&mut Cursor::new(traversal)).is_err());
        let mut utf8 = canonical.clone();
        utf8[NAME_OFFSET] = 0xff;
        assert!(Frame::read_from(&mut Cursor::new(utf8)).is_err());
        let mut bad_certificate = canonical;
        bad_certificate[6 + 32] = b'Z';
        assert!(Frame::read_from(&mut Cursor::new(bad_certificate)).is_err());
    }

    #[test]
    fn complete_is_untrusted_wire_data_not_an_authorizing_capability() {
        let o = example();
        // Any peer can encode a structurally well-formed receipt. This is
        // NOT evidence of authenticated peer identity or durable publication.
        // The eventual sender must check authenticated TLS peer AND exact
        // offer fields before displaying completion.
        let claimed = Receipt {
            transfer_id: o.id.clone(),
            peer: o.peer.clone(),
            manifest: o.manifest.clone(),
            bytes: o.bytes,
            sha256: o.sha256.clone(),
        };
        let mut bytes = Vec::new();
        Frame::Control(Control::Complete(claimed.clone()))
            .write_to(&mut bytes)
            .unwrap();
        assert_eq!(
            Frame::read_from(&mut Cursor::new(bytes)).unwrap(),
            Frame::Control(Control::Complete(claimed))
        );
    }
}
