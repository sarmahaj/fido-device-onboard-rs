use std::{convert::TryInto, ops::Deref, str::FromStr, string::ToString};

use serde_tuple::Serialize_tuple;

use crate::{
    constants::{DeviceSigType, HashType, RendezvousVariable, TransportProtocol},
    errors::Error,
    ownershipvoucher::{OwnershipVoucher, OwnershipVoucherHeader},
};

use openssl::hash::hash;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize_tuple, Deserialize, Clone)]
pub struct Hash {
    hash_type: HashType,
    value: Vec<u8>,
}

impl Hash {
    pub fn new(alg: Option<HashType>, data: &[u8]) -> Result<Self, Error> {
        let alg = alg.unwrap_or(HashType::Sha384);

        Ok(Hash {
            hash_type: alg,
            value: hash(alg.try_into()?, data)?.to_vec(),
        })
    }

    pub fn new_from_data(hash_type: HashType, value: Vec<u8>) -> Self {
        Hash { hash_type, value }
    }

    pub fn get_type(&self) -> HashType {
        self.hash_type
    }

    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub fn compare_data(&self, other: &[u8]) -> Result<(), Error> {
        let other_digest = hash(self.hash_type.try_into()?, other)?;

        // Compare
        if openssl::memcmp::eq(&self.value, &other_digest) {
            Ok(())
        } else {
            Err(Error::IncorrectHash)
        }
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:?})", hex::encode(&self.value), self.hash_type)
    }
}

pub type HMac = Hash;

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SigInfo {
    sig_type: DeviceSigType, // sgType
    info: Vec<u8>,           // Info
}

impl SigInfo {
    pub fn new(dst: DeviceSigType, info: Vec<u8>) -> Self {
        SigInfo {
            sig_type: dst,
            info,
        }
    }

    pub fn sig_type(&self) -> DeviceSigType {
        self.sig_type
    }

    pub fn info(&self) -> &[u8] {
        &self.info
    }
}

fn new_nonce_or_guid_val() -> Result<[u8; 16], Error> {
    let mut val = [0u8; 16];

    openssl::rand::rand_bytes(&mut val)?;

    Ok(val)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Nonce([u8; 16]);

impl Nonce {
    pub fn new() -> Result<Nonce, Error> {
        Ok(Nonce(new_nonce_or_guid_val()?))
    }

    pub fn from_value(val: &[u8]) -> Result<Self, Error> {
        Ok(Nonce(val.try_into().map_err(|_| Error::IncorrectNonce)?))
    }

    pub fn value(&self) -> &[u8] {
        &self.0
    }

    pub fn compare(&self, other: &Nonce) -> Result<(), Error> {
        // Compare
        if openssl::memcmp::eq(&self.0, &other.0) {
            Ok(())
        } else {
            Err(Error::IncorrectHash)
        }
    }
}

impl ToString for Nonce {
    fn to_string(&self) -> String {
        hex::encode(&self.0)
    }
}

impl FromStr for Nonce {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Ok(Nonce(hex::decode(s).unwrap().try_into().unwrap()))
    }
}

impl Deref for Nonce {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
pub struct Guid([u8; 16]);

impl Guid {
    pub fn new() -> Result<Guid, Error> {
        Ok(Guid(new_nonce_or_guid_val()?))
    }

    fn as_uuid(&self) -> uuid::Uuid {
        uuid::Uuid::from_bytes(self.0)
    }
}

impl FromStr for Guid {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Guid, uuid::Error> {
        Ok(Guid(uuid::Uuid::from_str(s)?.as_bytes().to_owned()))
    }
}

impl ToString for Guid {
    fn to_string(&self) -> String {
        self.as_uuid().to_string()
    }
}

impl Deref for Guid {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub use std::net::{IpAddr as IPAddress, Ipv4Addr as IP4, Ipv6Addr as IP6};

pub type DNSAddress = String;
pub type Port = u16;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RendezvousInfo(Vec<RendezvousDirective>);

impl RendezvousInfo {
    pub fn new(directives: Vec<RendezvousDirective>) -> RendezvousInfo {
        RendezvousInfo(directives)
    }

    pub fn values(&self) -> &[RendezvousDirective] {
        &self.0
    }
}

pub type RendezvousDirective = Vec<RendezvousInstruction>;
pub type RendezvousInstruction = (RendezvousVariable, CborSimpleType);

// TODO: This sends serde_cbor outwards. Possibly re-do this
pub type CborSimpleType = serde_cbor::Value;

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO2AddressEntry {
    ip: Option<IPAddress>,       // RVIP
    dns: Option<DNSAddress>,     // RVDNS
    port: Port,                  // RVPort
    protocol: TransportProtocol, // RVProtocol
}

impl TO2AddressEntry {
    pub fn new(
        ip: Option<IPAddress>,
        dns: Option<DNSAddress>,
        port: Port,
        protocol: TransportProtocol,
    ) -> Self {
        TO2AddressEntry {
            ip,
            dns,
            port,
            protocol,
        }
    }

    pub fn ip(&self) -> Option<&IPAddress> {
        self.ip.as_ref()
    }

    pub fn dns(&self) -> Option<&DNSAddress> {
        self.dns.as_ref()
    }

    pub fn port(&self) -> Port {
        self.port
    }

    pub fn protocol(&self) -> TransportProtocol {
        self.protocol
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO0Data {
    ownership_voucher: OwnershipVoucher,
    wait_seconds: u32,
    nonce: Nonce,
}

impl TO0Data {
    pub fn new(ownership_voucher: OwnershipVoucher, wait_seconds: u32, nonce: Nonce) -> Self {
        TO0Data {
            ownership_voucher,
            wait_seconds,
            nonce,
        }
    }

    pub fn ownership_voucher(&self) -> &OwnershipVoucher {
        &self.ownership_voucher
    }

    pub fn wait_seconds(&self) -> u32 {
        self.wait_seconds
    }

    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO1DataPayload {
    to2_addresses: Vec<TO2AddressEntry>,
    to1d_to_to0d_hash: Hash,
}

impl TO1DataPayload {
    pub fn new(to2_addresses: Vec<TO2AddressEntry>, to1d_to_to0d_hash: Hash) -> Self {
        TO1DataPayload {
            to2_addresses,
            to1d_to_to0d_hash,
        }
    }

    pub fn to2_addresses(&self) -> &[TO2AddressEntry] {
        &self.to2_addresses
    }

    pub fn to1d_to_to0d_hash(&self) -> &Hash {
        &self.to1d_to_to0d_hash
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO2ProveDevicePayload {
    b_key_exchange: KeyExchange,
}

impl TO2ProveDevicePayload {
    pub fn new(b_key_exchange: KeyExchange) -> Self {
        TO2ProveDevicePayload { b_key_exchange }
    }

    pub fn b_key_exchange(&self) -> &KeyExchange {
        &self.b_key_exchange
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ServiceInfo(Vec<(String, CborSimpleType)>);

impl ServiceInfo {
    pub fn new() -> Self {
        ServiceInfo(Vec::new())
    }

    pub fn add(&mut self, module: String, key: String, value: CborSimpleType) {
        self.0.push((format!("{}:{}", module, key), value));
    }

    pub fn iter(&self) -> ServiceInfoIter {
        ServiceInfoIter { info: self, pos: 0 }
    }

    pub fn values(&self) -> Result<Vec<(String, String, CborSimpleType)>, Error> {
        self.0
            .iter()
            .map(|(k, v)| match k.find(':') {
                None => Err(Error::InconsistentValue(
                    "ServiceInfo key missing module separation",
                )),
                Some(pos) => {
                    let (module, key) = k.split_at(pos);
                    Ok((module.to_string(), key.to_string(), v.clone()))
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct ServiceInfoIter<'a> {
    info: &'a ServiceInfo,
    pos: usize,
}

impl Iterator for ServiceInfoIter<'_> {
    type Item = (String, String, CborSimpleType);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.info.0.len() {
            return None;
        }
        let (module_key, val) = &self.info.0[self.pos];
        self.pos += 1;

        // When it's stable, use str.split_once
        let split_pos = match module_key.find(':') {
            None => {
                log::error!("ServiceInfo module_key missing colon: {}", module_key);
                return None;
            }
            Some(v) => v,
        };

        let (module, key) = module_key.split_at(split_pos);
        Some((module.to_string(), key.to_string(), val.clone()))
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct TO2ProveOVHdrPayload {
    ov_header: OwnershipVoucherHeader,
    num_ov_entries: u16,
    hmac: HMac,
    nonce5: Nonce,
    b_signature_info: SigInfo,
    a_key_exchange: KeyExchange,
}

impl TO2ProveOVHdrPayload {
    pub fn new(
        ov_header: OwnershipVoucherHeader,
        num_ov_entries: u16,
        hmac: HMac,
        nonce5: Nonce,
        b_signature_info: SigInfo,
        a_key_exchange: KeyExchange,
    ) -> Self {
        TO2ProveOVHdrPayload {
            ov_header,
            num_ov_entries,
            hmac,
            nonce5,
            b_signature_info,
            a_key_exchange,
        }
    }

    pub fn ov_header(&self) -> &OwnershipVoucherHeader {
        &self.ov_header
    }

    pub fn num_ov_entries(&self) -> u16 {
        self.num_ov_entries
    }

    pub fn hmac(&self) -> &HMac {
        &self.hmac
    }

    pub fn nonce5(&self) -> &Nonce {
        &self.nonce5
    }

    pub fn b_signature_info(&self) -> &SigInfo {
        &self.b_signature_info
    }

    pub fn a_key_exchange(&self) -> &KeyExchange {
        &self.a_key_exchange
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MAROEPrefix(Vec<u8>);

impl MAROEPrefix {
    pub fn new(data: Vec<u8>) -> Self {
        MAROEPrefix(data)
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyExchange(Vec<u8>);

impl KeyExchange {
    pub fn new(value: Vec<u8>) -> Self {
        KeyExchange(value)
    }

    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct DeviceCredential {
    pub active: bool,           // Active
    pub protver: u16,           // ProtVer
    pub hmac_secret: Vec<u8>,   // HmacSecret
    pub device_info: String,    // DeviceInfo
    pub guid: Guid,             // Guid
    pub rvinfo: RendezvousInfo, // RVInfo
    pub pubkey_hash: Hash,      // PubKeyHash

    // Custom from here
    pub private_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageProtocolInfo {
    token: Option<Vec<u8>>,
}

#[derive(Debug, Serialize_tuple, Deserialize)]
pub struct SizedMessage {
    msglen: u16,
    msgtype: crate::constants::MessageType,
    protver: u16,
    protocol_info: MessageProtocolInfo,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum KexSuite {
    ECDH256,
    ECDH384,
}

impl FromStr for KexSuite {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match &s.to_lowercase()[..] {
            "ecdh256" => Ok(KexSuite::ECDH256),
            "ecdh384" => Ok(KexSuite::ECDH384),
            other => Err(Error::InvalidSuiteName(other.to_string())),
        }
    }
}

impl ToString for KexSuite {
    fn to_string(&self) -> String {
        match self {
            KexSuite::ECDH256 => "ECDH256".to_string(),
            KexSuite::ECDH384 => "ECDH384".to_string(),
        }
    }
}

impl Serialize for KexSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for KexSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KexSuiteVisitor;

        impl<'de> serde::de::Visitor<'de> for KexSuiteVisitor {
            type Value = KexSuite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a kexsuite string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                KexSuite::from_str(v).map_err(|_| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(v),
                        &"a valid kex suite",
                    )
                })
            }
        }

        deserializer.deserialize_str(KexSuiteVisitor)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CipherSuite {
    A128GCM,
    A256GCM,
}

impl FromStr for CipherSuite {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match &s.to_lowercase()[..] {
            "a128gcm" => Ok(CipherSuite::A128GCM),
            "a256gcm" => Ok(CipherSuite::A256GCM),
            other => Err(Error::InvalidSuiteName(other.to_string())),
        }
    }
}

impl ToString for CipherSuite {
    fn to_string(&self) -> String {
        match self {
            CipherSuite::A128GCM => "A128GCM".to_string(),
            CipherSuite::A256GCM => "A256GCM".to_string(),
        }
    }
}

impl Serialize for CipherSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for CipherSuite {
    fn deserialize<D>(deserializer: D) -> Result<CipherSuite, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CipherSuiteVisitor;

        impl<'de> serde::de::Visitor<'de> for CipherSuiteVisitor {
            type Value = CipherSuite;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a ciphersuite string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                CipherSuite::from_str(v).map_err(|_| {
                    serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(v),
                        &"a valid cipher suite",
                    )
                })
            }
        }

        deserializer.deserialize_str(CipherSuiteVisitor)
    }
}
