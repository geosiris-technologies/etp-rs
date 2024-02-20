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
pub struct PutGrowingDataObjectsHeaderResponse {
    #[serde(rename = "success")]
    pub success: HashMap<String, String>,
}

fn putgrowingdataobjectsheaderresponse_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for PutGrowingDataObjectsHeaderResponse {
    fn avro_schema(&self) -> Option<Schema> {
        putgrowingdataobjectsheaderresponse_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for PutGrowingDataObjectsHeaderResponse {}

impl AvroDeserializable for PutGrowingDataObjectsHeaderResponse {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<PutGrowingDataObjectsHeaderResponse> {
        let record = from_avro_datum(
            &putgrowingdataobjectsheaderresponse_avro_schema().unwrap(),
            input,
            None,
        )
        .unwrap();
        from_value::<PutGrowingDataObjectsHeaderResponse>(&record)
    }
}

impl ETPMetadata for PutGrowingDataObjectsHeaderResponse {
    fn protocol(&self) -> i32 {
        6
    }
    fn message_type(&self) -> i32 {
        17
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

impl PutGrowingDataObjectsHeaderResponse {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::GrowingObject_PutGrowingDataObjectsHeaderResponse(self.clone())
    }
}

impl Default for PutGrowingDataObjectsHeaderResponse {
    /* Protocol 6, MessageType : 17 */
    fn default() -> PutGrowingDataObjectsHeaderResponse {
        PutGrowingDataObjectsHeaderResponse {
            success: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.GrowingObject",
    "name": "PutGrowingDataObjectsHeaderResponse",
    "protocol": "6",
    "messageType": "17",
    "senderRole": "store",
    "protocolRoles": "store,customer",
    "multipartFlag": true,
    "fields": [
        {
            "name": "success",
            "type": {
                "type": "map",
                "values": "string"
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.GrowingObject.PutGrowingDataObjectsHeaderResponse",
    "depends": []
}"#;
