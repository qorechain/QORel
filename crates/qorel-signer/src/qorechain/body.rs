//! `TxBody` handling: the canonical body the chain re-derives (`B0`), and the
//! policy that refuses a body the chain would not accept.
//!
//! What the chain does (x/pqc ante, Cosmos SDK 0.53 decoder): decode the
//! received body, drop every critical extension option whose type URL is the
//! hybrid signature, normalise an empty list to none, re-encode. Unknown
//! top-level fields are dropped by that re-encode while the classical
//! signature still covers them, and the Cosmos lane accepts the hybrid
//! signature as its ONLY critical extension option. So the body QORel signs
//! must carry no extension option of its own, no `unordered` flag, no
//! unknown field, and must already be in canonical encoding.

use prost::Message;

use super::HYBRID_SIG_TYPE_URL;
use crate::SignerError;

/// `google.protobuf.Any`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoAny {
    /// Type URL.
    #[prost(string, tag = "1")]
    pub type_url: String,
    /// Encoded value.
    #[prost(bytes = "vec", tag = "2")]
    pub value: Vec<u8>,
}

/// `google.protobuf.Timestamp`.
#[derive(Clone, PartialEq, Message)]
pub struct ProtoTimestamp {
    /// Seconds.
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    /// Nanoseconds.
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

/// `cosmos.tx.v1beta1.TxBody` (Cosmos SDK 0.53 field set).
#[derive(Clone, PartialEq, Message)]
pub struct ProtoTxBody {
    /// Messages.
    #[prost(message, repeated, tag = "1")]
    pub messages: Vec<ProtoAny>,
    /// Memo.
    #[prost(string, tag = "2")]
    pub memo: String,
    /// Timeout height.
    #[prost(uint64, tag = "3")]
    pub timeout_height: u64,
    /// Unordered flag.
    #[prost(bool, tag = "4")]
    pub unordered: bool,
    /// Timeout timestamp.
    #[prost(message, optional, tag = "5")]
    pub timeout_timestamp: Option<ProtoTimestamp>,
    /// Critical extension options.
    #[prost(message, repeated, tag = "1023")]
    pub extension_options: Vec<ProtoAny>,
    /// Non-critical extension options.
    #[prost(message, repeated, tag = "2047")]
    pub non_critical_extension_options: Vec<ProtoAny>,
}

const FIELD_MESSAGES: u32 = 1;
const FIELD_MEMO: u32 = 2;
const FIELD_TIMEOUT_HEIGHT: u32 = 3;
const FIELD_UNORDERED: u32 = 4;
const FIELD_TIMEOUT_TIMESTAMP: u32 = 5;
const FIELD_EXTENSION_OPTIONS: u32 = 1023;
const FIELD_NON_CRITICAL_EXTENSION_OPTIONS: u32 = 2047;

/// `B0` as the chain computes it from a full body: the hybrid signature
/// option removed, everything else re-encoded canonically.
pub fn strip_pqc_extension(body: &[u8]) -> Result<Vec<u8>, SignerError> {
    let mut tx_body = ProtoTxBody::decode(body)
        .map_err(|e| SignerError::Invalid(format!("cannot decode TxBody: {e}")))?;
    tx_body
        .extension_options
        .retain(|opt| opt.type_url != HYBRID_SIG_TYPE_URL);
    Ok(tx_body.encode_to_vec())
}

/// Refuses a body (without the hybrid option) that the chain would reject
/// once the hybrid option is added, or whose bytes differ from the canonical
/// form the chain will re-derive.
pub fn check_body_policy(body_without_ext: &[u8]) -> Result<(), SignerError> {
    for field in top_level_fields(body_without_ext)? {
        match field {
            FIELD_MESSAGES | FIELD_MEMO | FIELD_TIMEOUT_HEIGHT | FIELD_TIMEOUT_TIMESTAMP => {}
            FIELD_EXTENSION_OPTIONS => {
                return Err(SignerError::BodyPolicy(
                    "the body already carries a critical extension option; the hybrid \
                     signature must be the only one"
                        .into(),
                ))
            }
            FIELD_NON_CRITICAL_EXTENSION_OPTIONS => {
                return Err(SignerError::BodyPolicy(
                    "non-critical extension options are not supported on this chain".into(),
                ))
            }
            FIELD_UNORDERED => {
                return Err(SignerError::BodyPolicy(
                    "unordered transactions are not enabled on this chain".into(),
                ))
            }
            other => {
                return Err(SignerError::BodyPolicy(format!(
                    "unknown TxBody field {other}: the chain drops it from the signed bytes"
                )))
            }
        }
    }
    let canonical = ProtoTxBody::decode(body_without_ext)
        .map_err(|e| SignerError::Invalid(format!("cannot decode TxBody: {e}")))?
        .encode_to_vec();
    if canonical != body_without_ext {
        return Err(SignerError::BodyPolicy(
            "the body is not canonically encoded; the chain would sign different bytes".into(),
        ));
    }
    Ok(())
}

/// The field numbers of the top-level records, in wire order.
fn top_level_fields(mut buf: &[u8]) -> Result<Vec<u32>, SignerError> {
    let bad = |m: &str| SignerError::Invalid(format!("malformed TxBody: {m}"));
    let mut fields = Vec::new();
    while !buf.is_empty() {
        let key = read_varint(&mut buf).ok_or_else(|| bad("truncated key"))?;
        let field = u32::try_from(key >> 3).map_err(|_| bad("field number out of range"))?;
        if field == 0 {
            return Err(bad("field number 0"));
        }
        let skip = match key & 7 {
            0 => {
                read_varint(&mut buf).ok_or_else(|| bad("truncated varint"))?;
                0
            }
            1 => 8,
            2 => {
                let len = read_varint(&mut buf).ok_or_else(|| bad("truncated length"))?;
                usize::try_from(len).map_err(|_| bad("length out of range"))?
            }
            5 => 4,
            _ => return Err(bad("unsupported wire type")),
        };
        if skip > buf.len() {
            return Err(bad("record longer than the body"));
        }
        buf = &buf[skip..];
        fields.push(field);
    }
    Ok(fields)
}

fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10 {
        let (&byte, rest) = buf.split_first()?;
        *buf = rest;
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(f: impl FnOnce(&mut ProtoTxBody)) -> Vec<u8> {
        let mut b = ProtoTxBody {
            messages: vec![ProtoAny {
                type_url: "/ibc.core.channel.v1.MsgRecvPacket".into(),
                value: vec![1, 2, 3],
            }],
            memo: "qorel".into(),
            ..Default::default()
        };
        f(&mut b);
        b.encode_to_vec()
    }

    #[test]
    fn plain_relay_body_passes() {
        check_body_policy(&body(|_| {})).unwrap();
        check_body_policy(&body(|b| b.timeout_height = 10)).unwrap();
    }

    #[test]
    fn unordered_is_refused() {
        let err = check_body_policy(&body(|b| b.unordered = true)).unwrap_err();
        assert!(matches!(err, SignerError::BodyPolicy(_)), "{err}");
    }

    #[test]
    fn unknown_field_is_refused() {
        let mut b = body(|_| {});
        // field 1500, varint 1: key = 1500 << 3 = 12000 -> e0 5d
        b.extend_from_slice(&[0xe0, 0x5d, 0x01]);
        assert!(check_body_policy(&b).is_err());
    }

    #[test]
    fn non_critical_options_are_refused() {
        let b = body(|b| {
            b.non_critical_extension_options.push(ProtoAny {
                type_url: "/x".into(),
                value: vec![],
            })
        });
        assert!(check_body_policy(&b).is_err());
    }

    #[test]
    fn non_canonical_encoding_is_refused() {
        // memo first, then messages: valid protobuf, not canonical order.
        let canonical = body(|_| {});
        let msgs = ProtoTxBody {
            messages: vec![ProtoAny {
                type_url: "/ibc.core.channel.v1.MsgRecvPacket".into(),
                value: vec![1, 2, 3],
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let memo = &canonical[msgs.len()..];
        let reordered = [memo, &msgs[..]].concat();
        assert_ne!(reordered, canonical);
        assert!(check_body_policy(&reordered).is_err());
    }

    #[test]
    fn malformed_bytes_are_an_error_not_a_panic() {
        for bad in [&[0x0a, 0x05, 0x01][..], &[0xff; 11], &[0x00], &[0x0b]] {
            assert!(check_body_policy(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn strip_removes_only_the_hybrid_option() {
        let with = body(|b| {
            b.extension_options.push(ProtoAny {
                type_url: HYBRID_SIG_TYPE_URL.into(),
                value: vec![8, 1],
            })
        });
        assert_eq!(strip_pqc_extension(&with).unwrap(), body(|_| {}));
    }
}
