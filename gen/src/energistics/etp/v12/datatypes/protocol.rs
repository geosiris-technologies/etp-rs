// SPDX-FileCopyrightText: 2023 Geosiris
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(unused_imports)]
#![allow(non_camel_case_types)]
use crate::helpers::*;
use apache_avro::{Error, Schema};
use bytes;
use derivative::Derivative;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::helpers::Schemable;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::fmt;
use std::io::Read;
use std::slice::Iter;
use std::str::FromStr;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum Protocol {
    /* None */
    #[serde(rename(serialize = "Core", deserialize = "Core"))]
    Core = 0,
    #[serde(rename(serialize = "ChannelStreaming", deserialize = "ChannelStreaming"))]
    ChannelStreaming = 1,
    #[serde(rename(serialize = "ChannelDataFrame", deserialize = "ChannelDataFrame"))]
    ChannelDataFrame = 2,
    #[serde(rename(serialize = "Discovery", deserialize = "Discovery"))]
    Discovery = 3,
    #[serde(rename(serialize = "Store", deserialize = "Store"))]
    Store = 4,
    #[serde(rename(serialize = "StoreNotification", deserialize = "StoreNotification"))]
    StoreNotification = 5,
    #[serde(rename(serialize = "GrowingObject", deserialize = "GrowingObject"))]
    GrowingObject = 6,
    #[serde(rename(
        serialize = "GrowingObjectNotification",
        deserialize = "GrowingObjectNotification"
    ))]
    GrowingObjectNotification = 7,
    #[serde(rename(serialize = "DEPRECATED_8", deserialize = "DEPRECATED_8"))]
    DEPRECATED8 = 8,
    #[serde(rename(serialize = "DataArray", deserialize = "DataArray"))]
    DataArray = 9,
    #[serde(rename(serialize = "RESERVED_10", deserialize = "RESERVED_10"))]
    RESERVED10 = 10,
    #[serde(rename(serialize = "RESERVED_11", deserialize = "RESERVED_11"))]
    RESERVED11 = 11,
    #[serde(rename(serialize = "RESERVED_12", deserialize = "RESERVED_12"))]
    RESERVED12 = 12,
    #[serde(rename(serialize = "DiscoveryQuery", deserialize = "DiscoveryQuery"))]
    DiscoveryQuery = 13,
    #[serde(rename(serialize = "StoreQuery", deserialize = "StoreQuery"))]
    StoreQuery = 14,
    #[serde(rename(serialize = "RESERVED_15", deserialize = "RESERVED_15"))]
    RESERVED15 = 15,
    #[serde(rename(serialize = "GrowingObjectQuery", deserialize = "GrowingObjectQuery"))]
    GrowingObjectQuery = 16,
    #[serde(rename(serialize = "RESERVED_17", deserialize = "RESERVED_17"))]
    RESERVED17 = 17,
    #[serde(rename(serialize = "Transaction", deserialize = "Transaction"))]
    Transaction = 18,
    #[serde(rename(serialize = "RESERVED_19", deserialize = "RESERVED_19"))]
    RESERVED19 = 19,
    #[serde(rename(serialize = "RESERVED_20", deserialize = "RESERVED_20"))]
    RESERVED20 = 20,
    #[serde(rename(serialize = "ChannelSubscribe", deserialize = "ChannelSubscribe"))]
    ChannelSubscribe = 21,
    #[serde(rename(serialize = "ChannelDataLoad", deserialize = "ChannelDataLoad"))]
    ChannelDataLoad = 22,
    #[serde(rename(serialize = "RESERVED_23", deserialize = "RESERVED_23"))]
    RESERVED23 = 23,
    #[serde(rename(serialize = "Dataspace", deserialize = "Dataspace"))]
    Dataspace = 24,
    #[serde(rename(serialize = "SupportedTypes", deserialize = "SupportedTypes"))]
    SupportedTypes = 25,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Protocol::Core => "Core",
                Protocol::ChannelStreaming => "ChannelStreaming",
                Protocol::ChannelDataFrame => "ChannelDataFrame",
                Protocol::Discovery => "Discovery",
                Protocol::Store => "Store",
                Protocol::StoreNotification => "StoreNotification",
                Protocol::GrowingObject => "GrowingObject",
                Protocol::GrowingObjectNotification => "GrowingObjectNotification",
                Protocol::DEPRECATED8 => "DEPRECATED_8",
                Protocol::DataArray => "DataArray",
                Protocol::RESERVED10 => "RESERVED_10",
                Protocol::RESERVED11 => "RESERVED_11",
                Protocol::RESERVED12 => "RESERVED_12",
                Protocol::DiscoveryQuery => "DiscoveryQuery",
                Protocol::StoreQuery => "StoreQuery",
                Protocol::RESERVED15 => "RESERVED_15",
                Protocol::GrowingObjectQuery => "GrowingObjectQuery",
                Protocol::RESERVED17 => "RESERVED_17",
                Protocol::Transaction => "Transaction",
                Protocol::RESERVED19 => "RESERVED_19",
                Protocol::RESERVED20 => "RESERVED_20",
                Protocol::ChannelSubscribe => "ChannelSubscribe",
                Protocol::ChannelDataLoad => "ChannelDataLoad",
                Protocol::RESERVED23 => "RESERVED_23",
                Protocol::Dataspace => "Dataspace",
                Protocol::SupportedTypes => "SupportedTypes",
            }
        )
    }
}

impl FromStr for Protocol {
    type Err = ();
    fn from_str(input: &str) -> Result<Protocol, Self::Err> {
        match input {
            "Core" => Ok(Protocol::Core),
            "ChannelStreaming" => Ok(Protocol::ChannelStreaming),
            "ChannelDataFrame" => Ok(Protocol::ChannelDataFrame),
            "Discovery" => Ok(Protocol::Discovery),
            "Store" => Ok(Protocol::Store),
            "StoreNotification" => Ok(Protocol::StoreNotification),
            "GrowingObject" => Ok(Protocol::GrowingObject),
            "GrowingObjectNotification" => Ok(Protocol::GrowingObjectNotification),
            "DEPRECATED_8" => Ok(Protocol::DEPRECATED8),
            "DataArray" => Ok(Protocol::DataArray),
            "RESERVED_10" => Ok(Protocol::RESERVED10),
            "RESERVED_11" => Ok(Protocol::RESERVED11),
            "RESERVED_12" => Ok(Protocol::RESERVED12),
            "DiscoveryQuery" => Ok(Protocol::DiscoveryQuery),
            "StoreQuery" => Ok(Protocol::StoreQuery),
            "RESERVED_15" => Ok(Protocol::RESERVED15),
            "GrowingObjectQuery" => Ok(Protocol::GrowingObjectQuery),
            "RESERVED_17" => Ok(Protocol::RESERVED17),
            "Transaction" => Ok(Protocol::Transaction),
            "RESERVED_19" => Ok(Protocol::RESERVED19),
            "RESERVED_20" => Ok(Protocol::RESERVED20),
            "ChannelSubscribe" => Ok(Protocol::ChannelSubscribe),
            "ChannelDataLoad" => Ok(Protocol::ChannelDataLoad),
            "RESERVED_23" => Ok(Protocol::RESERVED23),
            "Dataspace" => Ok(Protocol::Dataspace),
            "SupportedTypes" => Ok(Protocol::SupportedTypes),
            _ => Err(()),
        }
    }
}

impl Protocol {
    pub fn iter() -> Iter<'static, Protocol> {
        static VEC_ENUM: [Protocol; 26] = [
            Protocol::Core,
            Protocol::ChannelStreaming,
            Protocol::ChannelDataFrame,
            Protocol::Discovery,
            Protocol::Store,
            Protocol::StoreNotification,
            Protocol::GrowingObject,
            Protocol::GrowingObjectNotification,
            Protocol::DEPRECATED8,
            Protocol::DataArray,
            Protocol::RESERVED10,
            Protocol::RESERVED11,
            Protocol::RESERVED12,
            Protocol::DiscoveryQuery,
            Protocol::StoreQuery,
            Protocol::RESERVED15,
            Protocol::GrowingObjectQuery,
            Protocol::RESERVED17,
            Protocol::Transaction,
            Protocol::RESERVED19,
            Protocol::RESERVED20,
            Protocol::ChannelSubscribe,
            Protocol::ChannelDataLoad,
            Protocol::RESERVED23,
            Protocol::Dataspace,
            Protocol::SupportedTypes,
        ];
        VEC_ENUM.iter()
    }
}
