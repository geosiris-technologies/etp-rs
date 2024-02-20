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

use crate::energistics::etp::v12::datatypes::data_array_types::get_data_subarrays_type::GetDataSubarraysType;
use crate::helpers::ETPMetadata;
use crate::helpers::Schemable;
use crate::protocols::ProtocolMessage;
use apache_avro::{from_avro_datum, from_value, AvroResult};
use std::io::Read;

#[derive(Debug, PartialEq, Clone, serde::Deserialize, serde::Serialize, Derivative)]
#[serde(rename_all = "PascalCase")]
pub struct GetDataSubarrays {
    #[serde(rename = "dataSubarrays")]
    pub data_subarrays: HashMap<String, GetDataSubarraysType>,
}

fn getdatasubarrays_avro_schema() -> Option<Schema> {
    match Schema::parse_str(AVRO_SCHEMA) {
        Ok(result) => Some(result),
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

impl Schemable for GetDataSubarrays {
    fn avro_schema(&self) -> Option<Schema> {
        getdatasubarrays_avro_schema()
    }
    fn avro_schema_str(&self) -> &'static str {
        AVRO_SCHEMA
    }
}

impl AvroSerializable for GetDataSubarrays {}

impl AvroDeserializable for GetDataSubarrays {
    fn avro_deserialize<R: Read>(input: &mut R) -> AvroResult<GetDataSubarrays> {
        let record =
            from_avro_datum(&getdatasubarrays_avro_schema().unwrap(), input, None).unwrap();
        from_value::<GetDataSubarrays>(&record)
    }
}

impl ETPMetadata for GetDataSubarrays {
    fn protocol(&self) -> i32 {
        9
    }
    fn message_type(&self) -> i32 {
        3
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

impl GetDataSubarrays {
    pub fn as_protocol_message(&self) -> ProtocolMessage {
        ProtocolMessage::DataArray_GetDataSubarrays(self.clone())
    }
}

impl Default for GetDataSubarrays {
    /* Protocol 9, MessageType : 3 */
    fn default() -> GetDataSubarrays {
        GetDataSubarrays {
            data_subarrays: HashMap::new(),
        }
    }
}

pub static AVRO_SCHEMA: &'static str = r#"{
    "type": "record",
    "namespace": "Energistics.Etp.v12.Protocol.DataArray",
    "name": "GetDataSubarrays",
    "protocol": "9",
    "messageType": "3",
    "senderRole": "customer",
    "protocolRoles": "store,customer",
    "multipartFlag": false,
    "fields": [
        {
            "name": "dataSubarrays",
            "type": {
                "type": "map",
                "values": {
                    "type": "record",
                    "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
                    "name": "GetDataSubarraysType",
                    "fields": [
                        {
                            "name": "uid",
                            "type": {
                                "type": "record",
                                "namespace": "Energistics.Etp.v12.Datatypes.DataArrayTypes",
                                "name": "DataArrayIdentifier",
                                "fields": [
                                    {
                                        "name": "uri",
                                        "type": "string"
                                    },
                                    {
                                        "name": "pathInResource",
                                        "type": "string"
                                    }
                                ],
                                "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArrayIdentifier",
                                "depends": []
                            }
                        },
                        {
                            "name": "starts",
                            "type": {
                                "type": "array",
                                "items": "long"
                            },
                            "default": []
                        },
                        {
                            "name": "counts",
                            "type": {
                                "type": "array",
                                "items": "long"
                            },
                            "default": []
                        }
                    ],
                    "fullName": "Energistics.Etp.v12.Datatypes.DataArrayTypes.GetDataSubarraysType",
                    "depends": [
                        "Energistics.Etp.v12.Datatypes.DataArrayTypes.DataArrayIdentifier"
                    ]
                }
            }
        }
    ],
    "fullName": "Energistics.Etp.v12.Protocol.DataArray.GetDataSubarrays",
    "depends": [
        "Energistics.Etp.v12.Datatypes.DataArrayTypes.GetDataSubarraysType"
    ]
}"#;
