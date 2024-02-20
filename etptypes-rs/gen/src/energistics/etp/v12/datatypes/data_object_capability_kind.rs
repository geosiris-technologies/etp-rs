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
pub enum DataObjectCapabilityKind {
    /* None */
    #[serde(rename(serialize = "ActiveTimeoutPeriod", deserialize = "ActiveTimeoutPeriod"))]
    ActiveTimeoutPeriod,
    #[serde(rename(
        serialize = "MaxContainedDataObjectCount",
        deserialize = "MaxContainedDataObjectCount"
    ))]
    MaxContainedDataObjectCount,
    #[serde(rename(serialize = "MaxDataObjectSize", deserialize = "MaxDataObjectSize"))]
    MaxDataObjectSize,
    #[serde(rename(
        serialize = "OrphanedChildrenPrunedOnDelete",
        deserialize = "OrphanedChildrenPrunedOnDelete"
    ))]
    OrphanedChildrenPrunedOnDelete,
    #[serde(rename(serialize = "SupportsGet", deserialize = "SupportsGet"))]
    SupportsGet,
    #[serde(rename(serialize = "SupportsPut", deserialize = "SupportsPut"))]
    SupportsPut,
    #[serde(rename(serialize = "SupportsDelete", deserialize = "SupportsDelete"))]
    SupportsDelete,
    #[serde(rename(
        serialize = "MaxSecondaryIndexCount",
        deserialize = "MaxSecondaryIndexCount"
    ))]
    MaxSecondaryIndexCount,
}

impl fmt::Display for DataObjectCapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DataObjectCapabilityKind::ActiveTimeoutPeriod => "ActiveTimeoutPeriod",
                DataObjectCapabilityKind::MaxContainedDataObjectCount =>
                    "MaxContainedDataObjectCount",
                DataObjectCapabilityKind::MaxDataObjectSize => "MaxDataObjectSize",
                DataObjectCapabilityKind::OrphanedChildrenPrunedOnDelete =>
                    "OrphanedChildrenPrunedOnDelete",
                DataObjectCapabilityKind::SupportsGet => "SupportsGet",
                DataObjectCapabilityKind::SupportsPut => "SupportsPut",
                DataObjectCapabilityKind::SupportsDelete => "SupportsDelete",
                DataObjectCapabilityKind::MaxSecondaryIndexCount => "MaxSecondaryIndexCount",
            }
        )
    }
}

impl FromStr for DataObjectCapabilityKind {
    type Err = ();
    fn from_str(input: &str) -> Result<DataObjectCapabilityKind, Self::Err> {
        match input {
            "ActiveTimeoutPeriod" => Ok(DataObjectCapabilityKind::ActiveTimeoutPeriod),
            "MaxContainedDataObjectCount" => {
                Ok(DataObjectCapabilityKind::MaxContainedDataObjectCount)
            }
            "MaxDataObjectSize" => Ok(DataObjectCapabilityKind::MaxDataObjectSize),
            "OrphanedChildrenPrunedOnDelete" => {
                Ok(DataObjectCapabilityKind::OrphanedChildrenPrunedOnDelete)
            }
            "SupportsGet" => Ok(DataObjectCapabilityKind::SupportsGet),
            "SupportsPut" => Ok(DataObjectCapabilityKind::SupportsPut),
            "SupportsDelete" => Ok(DataObjectCapabilityKind::SupportsDelete),
            "MaxSecondaryIndexCount" => Ok(DataObjectCapabilityKind::MaxSecondaryIndexCount),
            _ => Err(()),
        }
    }
}

impl DataObjectCapabilityKind {
    pub fn iter() -> Iter<'static, DataObjectCapabilityKind> {
        static VEC_ENUM: [DataObjectCapabilityKind; 8] = [
            DataObjectCapabilityKind::ActiveTimeoutPeriod,
            DataObjectCapabilityKind::MaxContainedDataObjectCount,
            DataObjectCapabilityKind::MaxDataObjectSize,
            DataObjectCapabilityKind::OrphanedChildrenPrunedOnDelete,
            DataObjectCapabilityKind::SupportsGet,
            DataObjectCapabilityKind::SupportsPut,
            DataObjectCapabilityKind::SupportsDelete,
            DataObjectCapabilityKind::MaxSecondaryIndexCount,
        ];
        VEC_ENUM.iter()
    }
}
