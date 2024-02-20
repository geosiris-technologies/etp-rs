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
pub struct GetGrowingDataObjectsHeader {
    #[serde(rename = "uris")]
    pub uris: HashMap<String, String>,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("xml")"#))]
    pub format: String,
}

fn getgrowingdataobjectsheader_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetGrowingDataObjectsHeader {
    fn avro_schema(&self) -> Option<Schema> {
        getgrowingdataobjectsheader_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetGrowingDataObjectsHeader {}

impl AvroDeserializable for GetGrowingDataObjectsHeader {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetGrowingDataObjectsHeader> {
        let record = from_avro_datum(
            &getgrowingdataobjectsheader_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<GetGrowingDataObjectsHeader>(&record)
    }
}

impl ETPMetadata for GetGrowingDataObjectsHeader {
    fn protocol(&self) -> i32 {
        6
    }
    fn message_type(&self) -> i32 {
        14
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

impl GetGrowingDataObjectsHeader {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObject_GetGrowingDataObjectsHeader(self.clone())
    }
}

impl Default for GetGrowingDataObjectsHeader {
    /* Protocol 6, MessageType : 14 */
    fn default() -> GetGrowingDataObjectsHeader {
        GetGrowingDataObjectsHeader {
            uris: HashMap::new(),
            format: "xml".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObject",
    "name": "GetGrowingDataObjectsHeader",
    "protocol": "6",
    "messageType": "14",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "uris",
            "type": {
                "type": "map",
                "values": "string"
            }
        },
        {
            "name": "format",
            "type": "string",
            "default": "xml"
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObject.GetGrowingDataObjectsHeader",
    "depends": []
}"#;
