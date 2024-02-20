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
pub struct GetDeletedResources {
    #[serde(rename = "dataspaceUri")]
    pub dataspace_uri: String,

    #[serde(rename = "deleteTimeFilter")]
    pub delete_time_filter: Option<i64>,

    #[serde(rename = "dataObjectTypes")]
    #[derivative(Default(value = "Vec::new()"))]
    pub data_object_types: Vec<String>,
}

fn getdeletedresources_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetDeletedResources {
    fn avro_schema(&self) -> Option<Schema> {
        getdeletedresources_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetDeletedResources {}

impl AvroDeserializable for GetDeletedResources {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetDeletedResources> {
        let record =
            from_avro_datum(&getdeletedresources_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetDeletedResources>(&record)
    }
}

impl ETPMetadata for GetDeletedResources {
    fn protocol(&self) -> i32 {
        3
    }
    fn message_type(&self) -> i32 {
        5
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

impl GetDeletedResources {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::Discovery_GetDeletedResources(self.clone())
    }
}

impl GetDeletedResources {
    /* Protocol 3, MessageType : 5 */
    pub fn default_with_params(delete_time_filter: Option<i64>) -> GetDeletedResources {
        GetDeletedResources {
            dataspace_uri: "".to_string(),
            delete_time_filter,
            data_object_types: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.Discovery",
    "name": "GetDeletedResources",
    "protocol": "3",
    "messageType": "5",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "dataspaceUri",
            "type": "string"
        },
        {
            "name": "deleteTimeFilter",
            "type": [
                "null",
                "long"
            ]
        },
        {
            "name": "dataObjectTypes",
            "type": {
                "type": "array",
                "items": "string"
            },
            "default": []
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.Discovery.GetDeletedResources",
    "depends": []
}"#;
