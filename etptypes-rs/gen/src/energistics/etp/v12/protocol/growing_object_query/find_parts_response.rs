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

use crate::energistics::etp::v12::datatypes::object::object_part::ObjectPart;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct FindPartsResponse {
    #[serde(rename = "uri")]
    pub uri: String,

    #[serde(rename = "serverSortOrder")]
    pub server_sort_order: String,

    #[serde(rename = "format")]
    #[derivative(Default(value = r#"String::from("xml")"#))]
    pub format: String,

    #[serde(rename = "parts")]
    #[derivative(Default(value = "Vec::new()"))]
    pub parts: Vec<ObjectPart>,
}

fn findpartsresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for FindPartsResponse {
    fn avro_schema(&self) -> Option<Schema> {
        findpartsresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for FindPartsResponse {}

impl AvroDeserializable for FindPartsResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<FindPartsResponse> {
        let record =
            from_avro_datum(&findpartsresponse_avro_schema().unwrap(), input, None).unwrap();
        from_value::<FindPartsResponse>(&record)
    }
}

impl ETPMetadata for FindPartsResponse {
    fn protocol(&self) -> i32 {
        16
    }
    fn message_type(&self) -> i32 {
        2
    }
    fn sender_role(&self) -> Vec<Role> {
        vec![Role::Store]
    }
    fn protocol_roles(&self) -> Vec<Role> {
        vec![Role::Store, Role::Customer]
    }
    fn multipart_flag(&self) -> bool {
        true
    }
}

impl FindPartsResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObjectQuery_FindPartsResponse(self.clone())
    }
}

impl FindPartsResponse {
    /* Protocol 16, MessageType : 2 */
    pub fn default_with_params(uri: String) -> FindPartsResponse {
        FindPartsResponse {
            uri,
            server_sort_order: "".to_string(),
            format: "xml".to_string(),
            parts: vec![],
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObjectQuery",
    "name": "FindPartsResponse",
    "protocol": "16",
    "messageType": "2",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "uri",
            "type": "string"
        },
        {
            "name": "serverSortOrder",
            "type": "string"
        },
        {
            "name": "format",
            "type": "string",
            "default": "xml"
        },
        {
            "name": "parts",
            "type": {
                "type": "array",
                "items": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.Object",
                    "name": "ObjectPart",
                    "fields": [
                        {
                            "name": "uid",
                            "type": "string"
                        },
                        {
                            "name": "data",
                            "type": "bytes"
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.Object.ObjectPart",
                    "depends": []
                }
            },
            "default": []
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObjectQuery.FindPartsResponse",
    "depends": [
        "Energistics.Etp.v12.Datatypes.Object.ObjectPart"
    ]
}"#;
