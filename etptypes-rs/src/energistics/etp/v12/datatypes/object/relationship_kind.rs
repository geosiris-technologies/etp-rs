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
pub enum RelationshipKind {
    /* None */
    #[serde(rename(serialize = "Primary", deserialize = "Primary"))]
    Primary,
    #[serde(rename(serialize = "Secondary", deserialize = "Secondary"))]
    Secondary,
    #[serde(rename(serialize = "Both", deserialize = "Both"))]
    Both,
}

impl fmt::Display for RelationshipKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                RelationshipKind::Primary => "Primary",
                RelationshipKind::Secondary => "Secondary",
                RelationshipKind::Both => "Both",
            }
        )
    }
}

impl FromStr for RelationshipKind {
    type Err = ();
    fn from_str(input: &str) -> Result<RelationshipKind, Self::Err> {
        match input {
            "Primary" => Ok(RelationshipKind::Primary),
            "Secondary" => Ok(RelationshipKind::Secondary),
            "Both" => Ok(RelationshipKind::Both),
            _ => Err(()),
        }
    }
}

impl RelationshipKind {
    pub fn iter() -> Iter<'static, RelationshipKind> {
        static VEC_ENUM: [RelationshipKind; 3] = [
            RelationshipKind::Primary,
            RelationshipKind::Secondary,
            RelationshipKind::Both,
        ];
        VEC_ENUM.iter()
    }
}
