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
pub enum ProtocolCapabilityKind {
    /* None */
    #[serde(rename(
        serialize = "FrameChangeDetectionPeriod",
        deserialize = "FrameChangeDetectionPeriod"
    ))]
    FrameChangeDetectionPeriod,
    #[serde(rename(serialize = "MaxDataArraySize", deserialize = "MaxDataArraySize"))]
    MaxDataArraySize,
    #[serde(rename(serialize = "MaxDataObjectSize", deserialize = "MaxDataObjectSize"))]
    MaxDataObjectSize,
    #[serde(rename(
        serialize = "MaxFrameResponseRowCount",
        deserialize = "MaxFrameResponseRowCount"
    ))]
    MaxFrameResponseRowCount,
    #[serde(rename(serialize = "MaxIndexCount", deserialize = "MaxIndexCount"))]
    MaxIndexCount,
    #[serde(rename(
        serialize = "MaxRangeChannelCount",
        deserialize = "MaxRangeChannelCount"
    ))]
    MaxRangeChannelCount,
    #[serde(rename(
        serialize = "MaxRangeDataItemCount",
        deserialize = "MaxRangeDataItemCount"
    ))]
    MaxRangeDataItemCount,
    #[serde(rename(serialize = "MaxResponseCount", deserialize = "MaxResponseCount"))]
    MaxResponseCount,
    #[serde(rename(
        serialize = "MaxStreamingChannelsSessionCount",
        deserialize = "MaxStreamingChannelsSessionCount"
    ))]
    MaxStreamingChannelsSessionCount,
    #[serde(rename(
        serialize = "MaxSubscriptionSessionCount",
        deserialize = "MaxSubscriptionSessionCount"
    ))]
    MaxSubscriptionSessionCount,
    #[serde(rename(serialize = "MaxTransactionCount", deserialize = "MaxTransactionCount"))]
    MaxTransactionCount,
    #[serde(rename(
        serialize = "SupportsSecondaryIndexFiltering",
        deserialize = "SupportsSecondaryIndexFiltering"
    ))]
    SupportsSecondaryIndexFiltering,
    #[serde(rename(
        serialize = "TransactionTimeoutPeriod",
        deserialize = "TransactionTimeoutPeriod"
    ))]
    TransactionTimeoutPeriod,
}

impl fmt::Display for ProtocolCapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ProtocolCapabilityKind::FrameChangeDetectionPeriod => "FrameChangeDetectionPeriod",
                ProtocolCapabilityKind::MaxDataArraySize => "MaxDataArraySize",
                ProtocolCapabilityKind::MaxDataObjectSize => "MaxDataObjectSize",
                ProtocolCapabilityKind::MaxFrameResponseRowCount => "MaxFrameResponseRowCount",
                ProtocolCapabilityKind::MaxIndexCount => "MaxIndexCount",
                ProtocolCapabilityKind::MaxRangeChannelCount => "MaxRangeChannelCount",
                ProtocolCapabilityKind::MaxRangeDataItemCount => "MaxRangeDataItemCount",
                ProtocolCapabilityKind::MaxResponseCount => "MaxResponseCount",
                ProtocolCapabilityKind::MaxStreamingChannelsSessionCount =>
                    "MaxStreamingChannelsSessionCount",
                ProtocolCapabilityKind::MaxSubscriptionSessionCount =>
                    "MaxSubscriptionSessionCount",
                ProtocolCapabilityKind::MaxTransactionCount => "MaxTransactionCount",
                ProtocolCapabilityKind::SupportsSecondaryIndexFiltering =>
                    "SupportsSecondaryIndexFiltering",
                ProtocolCapabilityKind::TransactionTimeoutPeriod => "TransactionTimeoutPeriod",
            }
        )
    }
}

impl FromStr for ProtocolCapabilityKind {
    type Err = ();
    fn from_str(input: &str) -> Result<ProtocolCapabilityKind, Self::Err> {
        match input {
            "FrameChangeDetectionPeriod" => Ok(ProtocolCapabilityKind::FrameChangeDetectionPeriod),
            "MaxDataArraySize" => Ok(ProtocolCapabilityKind::MaxDataArraySize),
            "MaxDataObjectSize" => Ok(ProtocolCapabilityKind::MaxDataObjectSize),
            "MaxFrameResponseRowCount" => Ok(ProtocolCapabilityKind::MaxFrameResponseRowCount),
            "MaxIndexCount" => Ok(ProtocolCapabilityKind::MaxIndexCount),
            "MaxRangeChannelCount" => Ok(ProtocolCapabilityKind::MaxRangeChannelCount),
            "MaxRangeDataItemCount" => Ok(ProtocolCapabilityKind::MaxRangeDataItemCount),
            "MaxResponseCount" => Ok(ProtocolCapabilityKind::MaxResponseCount),
            "MaxStreamingChannelsSessionCount" => {
                Ok(ProtocolCapabilityKind::MaxStreamingChannelsSessionCount)
            }
            "MaxSubscriptionSessionCount" => {
                Ok(ProtocolCapabilityKind::MaxSubscriptionSessionCount)
            }
            "MaxTransactionCount" => Ok(ProtocolCapabilityKind::MaxTransactionCount),
            "SupportsSecondaryIndexFiltering" => {
                Ok(ProtocolCapabilityKind::SupportsSecondaryIndexFiltering)
            }
            "TransactionTimeoutPeriod" => Ok(ProtocolCapabilityKind::TransactionTimeoutPeriod),
            _ => Err(()),
        }
    }
}

impl ProtocolCapabilityKind {
    pub fn iter() -> Iter<'static, ProtocolCapabilityKind> {
        static VEC_ENUM: [ProtocolCapabilityKind; 13] = [
            ProtocolCapabilityKind::FrameChangeDetectionPeriod,
            ProtocolCapabilityKind::MaxDataArraySize,
            ProtocolCapabilityKind::MaxDataObjectSize,
            ProtocolCapabilityKind::MaxFrameResponseRowCount,
            ProtocolCapabilityKind::MaxIndexCount,
            ProtocolCapabilityKind::MaxRangeChannelCount,
            ProtocolCapabilityKind::MaxRangeDataItemCount,
            ProtocolCapabilityKind::MaxResponseCount,
            ProtocolCapabilityKind::MaxStreamingChannelsSessionCount,
            ProtocolCapabilityKind::MaxSubscriptionSessionCount,
            ProtocolCapabilityKind::MaxTransactionCount,
            ProtocolCapabilityKind::SupportsSecondaryIndexFiltering,
            ProtocolCapabilityKind::TransactionTimeoutPeriod,
        ];
        VEC_ENUM.iter()
    }
}
