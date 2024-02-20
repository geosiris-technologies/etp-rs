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
pub struct GetDataObjects {
    #[serde(rename = "uris")]
    pub uris: HashMap<String, String>,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("xml")"#))]
    pub format: String,
}

fn getdataobjects_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetDataObjects {
    fn avro_schema(&self) -> Option<Schema> {
        getdataobjects_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetDataObjects {}

impl AvroDeserializable for GetDataObjects {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetDataObjects> {
        let record = from_avro_datum(&getdataobjects_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetDataObjects>(&record)
    }
}

impl ETPMetadata for GetDataObjects {
    fn protocol(&self) -> i32 {
        4
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

impl GetDataObjects {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Store_GetDataObjects(self.clone())
    }
}

impl Default for GetDataObjects {
    /* Protocol 4, MessageType : 1 */
    fn default() -> GetDataObjects {
        GetDataObjects {
            uris: HashMap::new(),
            format: "xml".to_string(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Store",
    "name": "GetDataObjects",
    "protocol": "4",
    "messageType": "1",
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
    "fullName": "Energistics.Etp.v12.Protocol.Store.GetDataObjects",
    "depends": []
}"#;
