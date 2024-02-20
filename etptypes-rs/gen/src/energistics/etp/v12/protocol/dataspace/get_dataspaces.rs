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

use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;
#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetDataspaces {
    #[serde(rename = "storeLastWriteFilter")]
    pub store_last_write_filter: Option<i64>,
}

fn getdataspaces_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetDataspaces {
    fn avro_schema(&self) -> Option<Schema> {
        getdataspaces_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetDataspaces {}

impl AvroDeserializable for GetDataspaces {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetDataspaces> {
        let record = from_avro_datum(&getdataspaces_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetDataspaces>(&record)
    }
}

impl ETPMetadata for GetDataspaces {
    fn protocol(&self) -> i32 {
        24
    }
    fn message_type(&self) -> i32 {
        1
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Customer]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        false
    }
}

impl GetDataspaces {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Dataspace_GetDataspaces(self.clone())
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Dataspace",
    "name": "GetDataspaces",
    "protocol": "24",
    "messageType": "1",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "storeLastWriteFilter",
            "type": [
                "null",
                "long"
            ]
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Dataspace.GetDataspaces",
    "depends": []
}"#;
