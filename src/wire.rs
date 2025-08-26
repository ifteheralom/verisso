// wire.rs
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;

/// Convert to canonical bytes
pub fn to_canonical_bytes<T: CanonicalSerialize>(t: &T) -> Result<Vec<u8>, SerializationError> {
    let mut v = Vec::new();
    t.serialize_compressed(&mut v)?;
    Ok(v)
}

/// Convert from canonical bytes
pub fn from_canonical_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, SerializationError> {
    let mut r = bytes;
    T::deserialize_compressed(&mut r)
}

/// Base64 helpers (nice for JSON transports)
pub fn to_base64<T: CanonicalSerialize>(t: &T) -> Result<String, SerializationError> {
    Ok(base64::encode(to_canonical_bytes(t)?))
}

pub fn from_base64<T: CanonicalDeserialize>(s: &str) -> Result<T, SerializationError> {
    let bytes = base64::decode(s).map_err(|_| SerializationError::InvalidData)?;
    from_canonical_bytes(&bytes)
}

/// Generic serde wrapper for any Canonical*(De)serialize object.
/// This lets you put external crypto types into serde structs.
#[derive(Clone)]
pub struct Canonical<T>(pub T);

impl<T> Serialize for Canonical<T>
    where
        T: CanonicalSerialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = to_canonical_bytes(&self.0).map_err(serde::ser::Error::custom)?;
        // Use serde_bytes for compact binary-in-JSON; or swap to base64 as a string if you prefer
        serde_bytes::Serialize::serialize(&bytes, serializer)
    }
}

impl<'de, T> Deserialize<'de> for Canonical<T>
    where
        T: CanonicalDeserialize,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde_bytes::Deserialize::deserialize(deserializer)?;
        let t = from_canonical_bytes(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Canonical(t))
    }
}
