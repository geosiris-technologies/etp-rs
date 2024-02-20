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
pub enum ObjectChangeKind {
    /* None */
    #[serde(rename(serialize = "insert", deserialize = "insert"))]
    Insert,
    #[serde(rename(serialize = "update", deserialize = "update"))]
    Update,
    #[serde(rename(serialize = "authorized", deserialize = "authorized"))]
    Authorized,
    #[serde(rename(serialize = "joined", deserialize = "joined"))]
    Joined,
    #[serde(rename(serialize = "unjoined", deserialize = "unjoined"))]
    Unjoined,
    #[serde(rename(serialize = "joinedSubscription", deserialize = "joinedSubscription"))]
    JoinedSubscription,
    #[serde(rename(
        serialize = "unjoinedSubscription",
        deserialize = "unjoinedSubscription"
    ))]
    UnjoinedSubscription,
}

impl fmt::Display for ObjectChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ObjectChangeKind::Insert => "insert",
                ObjectChangeKind::Update => "update",
                ObjectChangeKind::Authorized => "authorized",
                ObjectChangeKind::Joined => "joined",
                ObjectChangeKind::Unjoined => "unjoined",
                ObjectChangeKind::JoinedSubscription => "joinedSubscription",
                ObjectChangeKind::UnjoinedSubscription => "unjoinedSubscription",
            }
        )
    }
}

impl FromStr for ObjectChangeKind {
    type Err = ();
    fn from_str(input: &str) -> Result<ObjectChangeKind, Self::Err> {
        match input {
            "insert" => Ok(ObjectChangeKind::Insert),
            "update" => Ok(ObjectChangeKind::Update),
            "authorized" => Ok(ObjectChangeKind::Authorized),
            "joined" => Ok(ObjectChangeKind::Joined),
            "unjoined" => Ok(ObjectChangeKind::Unjoined),
            "joinedSubscription" => Ok(ObjectChangeKind::JoinedSubscription),
            "unjoinedSubscription" => Ok(ObjectChangeKind::UnjoinedSubscription),
            _ => Err(()),
        }
    }
}

impl ObjectChangeKind {
    pub fn iter() -> Iter<'static, ObjectChangeKind> {
        static VEC_ENUM: [ObjectChangeKind; 7] = [
            ObjectChangeKind::Insert,
            ObjectChangeKind::Update,
            ObjectChangeKind::Authorized,
            ObjectChangeKind::Joined,
            ObjectChangeKind::Unjoined,
            ObjectChangeKind::JoinedSubscription,
            ObjectChangeKind::UnjoinedSubscription,
        ];
        VEC_ENUM.iter()
    }
}
