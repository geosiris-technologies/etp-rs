// SPDX-FileCopyrightText: 2023 Geosiris
// SPDX-License-Identifier: Apache-2.0 OR MIT
use etpproto::connection::ConnectionType;
use etpproto::connection::EtpConnection;
use etpproto::credentials::create_client_info;
use etpproto::message::decode_message;
use etpproto::message::EtpMessageHandler;
use etpproto::message::MessageHeaderFlag;
use etpproto::uri::Uri;
use etptypes::energistics::etp::v12::datatypes::contact::Contact;
use etptypes::energistics::etp::v12::datatypes::data_value::DataValue;
use etptypes::energistics::etp::v12::datatypes::data_value::UnionBooleanIntLongFloatDoubleStringArrayOfBooleanArrayOfNullableBooleanArrayOfIntArrayOfNullableIntArrayOfLongArrayOfNullableLongArrayOfFloatArrayOfDoubleArrayOfStringArrayOfBytesBytesAnySparseArray as U_TYPE;
use etptypes::energistics::etp::v12::datatypes::object::context_info::ContextInfo;
use etptypes::energistics::etp::v12::datatypes::object::context_scope_kind::ContextScopeKind;
use etptypes::energistics::etp::v12::datatypes::object::dataspace::Dataspace;
use etptypes::energistics::etp::v12::datatypes::object::relationship_kind::RelationshipKind;
use etptypes::energistics::etp::v12::datatypes::protocol::Protocol;
use etptypes::energistics::etp::v12::datatypes::server_capabilities::ServerCapabilities;
use etptypes::energistics::etp::v12::datatypes::supported_protocol::SupportedProtocol;
use etptypes::energistics::etp::v12::datatypes::uuid::random_uuid;
use etptypes::energistics::etp::v12::protocol::core::close_session::CloseSession;
use etptypes::energistics::etp::v12::protocol::core::open_session::OpenSession;
use etptypes::energistics::etp::v12::protocol::core::ping::Ping;
use etptypes::energistics::etp::v12::protocol::core::pong::Pong;
use etptypes::energistics::etp::v12::protocol::core::protocol_exception::ProtocolException;
use etptypes::energistics::etp::v12::protocol::core::request_session::RequestSession;
use etptypes::energistics::etp::v12::protocol::dataspace::delete_dataspaces::DeleteDataspaces;
use etptypes::energistics::etp::v12::protocol::dataspace::get_dataspaces::GetDataspaces;
use etptypes::energistics::etp::v12::protocol::dataspace::put_dataspaces::PutDataspaces;
use etptypes::energistics::etp::v12::protocol::discovery::get_resources::GetResources;
use etptypes::energistics::etp::v12::protocol::store::get_data_objects::GetDataObjects;
use etptypes::error::eunsupported_protocol;
use etptypes::helpers::time_to_etp;
use etptypes::helpers::AvroSerializable;
use etptypes::helpers::ETP12VERSION;
use etptypes::protocols::ProtocolMessage;
use std::collections::HashMap;
use std::time::SystemTime;

pub struct MyHandler {}

impl EtpMessageHandler for MyHandler {
    fn handle(
        &mut self,
        _header: MessageHeaderFlag,
        msg: &ProtocolMessage,
    ) -> Option<Vec<ProtocolMessage>> {
        println!("{:?} <=== ", msg);
        match msg {
            ProtocolMessage::Core_RequestSession(_rq) => Some(vec![OpenSession {
                application_name: "A server".to_string(),
                application_version: "1.0.1".to_string(),
                server_instance_id: random_uuid(),
                supported_protocols: vec![],
                supported_data_objects: vec![],
                supported_compression: "".to_string(),
                supported_formats: vec!["xml".to_string()],
                current_date_time: time_to_etp(SystemTime::now()),
                earliest_retained_change_time: time_to_etp(SystemTime::now()),
                session_id: random_uuid(),
                endpoint_capabilities: HashMap::new(),
            }
            .as_protocol_message()]),
            ProtocolMessage::Core_Ping(_ping) => Some(vec![Pong::default().as_protocol_message()]),
            ProtocolMessage::Core_Pong(_pong) => None,
            _ => Some(vec![ProtocolMessage::Core_ProtocolException(
                ProtocolException::default_with_params(Some(eunsupported_protocol())),
            )]),
        }
    }
}

/*
   ______                                          __
  / ____/___  ____ ___  ____ ___  ____ _____  ____/ /____
 / /   / __ \/ __ `__ \/ __ `__ \/ __ `/ __ \/ __  / ___/
/ /___/ /_/ / / / / / / / / / / / /_/ / / / / /_/ (__  )
\____/\____/_/ /_/ /_/_/ /_/ /_/\__,_/_/ /_/\__,_/____/
*/

pub fn send_command(command_and_params: Vec<&str>) -> Option<ProtocolMessage> {
    let entry_lc = command_and_params[0].to_lowercase();

    if entry_lc.starts_with("help") {
        println!("############");
        println!("#  HELPER  #");
        println!("############");
        println!(
            r#"[XXX] : replace XXX with your value
[XXX=Y] : replace XXX with your value, default is Y
[[XXX]] : optional parameter

    Help : show this menu

    Quit : hard quit (no CloseSession sent)
    Close : see "Quit"

    GetDataObject         [[XML|JSON]] [URI_1] [...] [URI_N]
    GetResources          [[uri=eml:/// or notUri=DataspaceName]]

    GetDataspaces
    PutDataspace          [NAME]
    DeleteDataspace       [NAME]

    Ping
    "#
        );
    }
    /*
       ______     __  ____
      / ____/__  / /_/ __ \___  _________  __  _______________  _____
     / / __/ _ \/ __/ /_/ / _ \/ ___/ __ \/ / / / ___/ ___/ _ \/ ___/
    / /_/ /  __/ /_/ _, _/  __(__  ) /_/ / /_/ / /  / /__/  __(__  )
    \____/\___/\__/_/ |_|\___/____/\____/\__,_/_/   \___/\___/____/
    */
    else if entry_lc.starts_with("getresource") {
        let mut uri = "eml:///".to_string();

        if command_and_params.len() > 1 {
            uri = command_and_params[1].to_string();
        }

        let uri_p = Uri::parse(&uri);
        if let Err(_u) = uri_p {
            // If argument is not a uri, try to use it as a dataspace name
            uri = format!("eml:///dataspace('{uri}')");
        }

        let getress = GetResources::default_with_params(
            ContextInfo {
                uri,
                depth: 1 as i32,
                data_object_types: vec![],
                navigable_edges: RelationshipKind::Both,
                include_secondary_targets: false,
                include_secondary_sources: false,
            },
            ContextScopeKind::TargetsOrSelf,
            None,
            None,
        );
        println!("SENDING GR : {:?}", getress);
        if let Err(e) = getress.avro_serialize() {
            eprintln!("{}", e);
            // handle the error properly here
        }
        return Some(getress.as_protocol_message());
    } else if entry_lc.starts_with("getdataobject") {
        if command_and_params.len() > 1 {
            let mut uris_start_idx = 1;

            let mut format = "xml".to_string();
            if command_and_params[1].to_lowercase() == "xml".to_string()
                || command_and_params[1].to_lowercase() == "json"
            {
                format = command_and_params[1].to_lowercase();
                uris_start_idx = 2;
            }

            let uris_params = &command_and_params[uris_start_idx..];

            let getress = GetDataObjects {
                uris: uris_params
                    .iter()
                    .enumerate()
                    .map(|(i, v)| (format!("{:?}", i), String::from(*v)))
                    .collect::<HashMap<_, _>>(),
                format,
            };
            println!("SENDING GR : {:?}", getress);
            if let Err(e) = getress.avro_serialize() {
                eprintln!("{}", e);
                // handle the error properly here
            }
            return Some(getress.as_protocol_message());
        } else {
            println!("No enough parameters");
        }
    }
    /*
        ____        __
       / __ \____ _/ /_____ __________  ____ _________
      / / / / __ `/ __/ __ `/ ___/ __ \/ __ `/ ___/ _ \
     / /_/ / /_/ / /_/ /_/ (__  ) /_/ / /_/ / /__/  __/
    /_____/\__,_/\__/\__,_/____/ .___/\__,_/\___/\___/
                              /_/
    */
    else if entry_lc.starts_with("getdataspace") {
        let get_dataspaces = GetDataspaces {
            store_last_write_filter: None,
        };
        println!("SENDING GDS : {:?}", get_dataspaces);
        if let Err(e) = get_dataspaces.avro_serialize() {
            eprintln!("{}", e);
            // handle the error properly here
        }
        return Some(get_dataspaces.as_protocol_message());
    } else if entry_lc.starts_with("putdataspace") {
        if command_and_params.len() > 1 {
            let dataspace_name = command_and_params[1];

            let put_dataspaces = PutDataspaces {
                dataspaces: HashMap::from([(
                    "0".to_string(),
                    Dataspace::default_with_params(
                        if dataspace_name.contains("eml:///") {
                            dataspace_name.to_string()
                        } else {
                            format!("eml:///dataspace('{dataspace_name}')")
                        },
                        date_now(),
                        date_now(),
                    ),
                )]),
            };
            println!("SENDING PDS : {:?}", put_dataspaces);
            if let Err(e) = put_dataspaces.avro_serialize() {
                eprintln!("{}", e);
                // handle the error properly here
            }
            return Some(put_dataspaces.as_protocol_message());
        } else {
            println!("No enough parameters");
        }
    } else if entry_lc.starts_with("deletedataspace") {
        if command_and_params.len() > 1 {
            let dataspace_name = command_and_params[1];

            let delete_dataspaces = DeleteDataspaces {
                uris: HashMap::from([(
                    "0".to_string(),
                    if dataspace_name.contains("eml:///") {
                        dataspace_name.to_string()
                    } else {
                        format!("eml:///dataspace('{dataspace_name}')")
                    },
                )]),
            };
            println!("SENDING DDS : {:?}", delete_dataspaces);
            if let Err(e) = delete_dataspaces.avro_serialize() {
                eprintln!("{}", e);
                // handle the error properly here
            }
            return Some(delete_dataspaces.as_protocol_message());
        }
    }
    /*
       ____  __  __
      / __ \/ /_/ /_  ___  _____
     / / / / __/ __ \/ _ \/ ___/
    / /_/ / /_/ / / /  __/ /
    \____/\__/_/ /_/\___/_/
    */
    else if entry_lc == "ping" {
        let now = SystemTime::now();
        let ping = Ping {
            current_date_time: time_to_etp(now),
        };
        return Some(ping.as_protocol_message());
    } else if entry_lc == "close" || entry_lc == "quit" {
        let close = CloseSession {
            reason: "Bye Bye".to_string(),
        };
        return Some(close.as_protocol_message());
    } else {
        println!("Unrecognized message. Please retry");
    }
    return None;
}

/*
    ____        _ __    __
   / __ )__  __(_) /___/ /__  __________
  / __  / / / / / / __  / _ \/ ___/ ___/
 / /_/ / /_/ / / / /_/ /  __/ /  (__  )
/_____/\__,_/_/_/\__,_/\___/_/  /____/
*/

pub fn get_request_session() -> RequestSession {
    let protocols = vec![
        SupportedProtocol {
            protocol: Protocol::Core as i32,
            protocol_version: ETP12VERSION,
            role: "Server".to_string(),
            protocol_capabilities: HashMap::new(),
        },
        SupportedProtocol {
            protocol: 3,
            protocol_version: ETP12VERSION,
            role: "Server".to_string(),
            protocol_capabilities: HashMap::new(),
        },
        SupportedProtocol {
            protocol: 4,
            protocol_version: ETP12VERSION,
            role: "Server".to_string(),
            protocol_capabilities: HashMap::new(),
        },
    ];

    let now = SystemTime::now();

    RequestSession {
        application_name: "etp-rs Client Library Application".to_string(),
        application_version: "0.1".to_string(),
        client_instance_id: random_uuid(),
        requested_protocols: protocols,
        supported_data_objects: vec![],
        supported_compression: vec!["gzip".to_string()],
        supported_formats: vec!["xml".to_string(), "json".to_string()],
        current_date_time: time_to_etp(now),
        earliest_retained_change_time: time_to_etp(now),
        server_authorization_required: false,
        endpoint_capabilities: HashMap::new(),
    }
}

pub fn date_now() -> i64 {
    let now = SystemTime::now();
    time_to_etp(now)
}

pub fn get_connection() -> EtpConnection {
    let ma = HashMap::from([
        (
            "ActiveTimeoutPeriod".to_string(),
            DataValue {
                item: Some(U_TYPE::Int(666)),
            },
        ),
        (
            "Nimp".to_string(),
            DataValue {
                item: Some(U_TYPE::Long(2)),
            },
        ),
        (
            "Nimp2".to_string(),
            DataValue {
                item: Some(U_TYPE::Long(3)),
            },
        ),
    ]);

    let connection: EtpConnection = EtpConnection::new(
        Some(create_client_info(None, None, None)),
        ConnectionType::Server,
        Some(ServerCapabilities {
            application_name: "etpproto-rs".to_string(),
            application_version: "1.0.0+1.2".to_string(),
            contact_information: Contact {
                organization_name: "Geosiris".to_string(),
                contact_name: "Valentin Gauthier".to_string(),
                contact_phone: "007".to_string(),
                contact_email: "valentin.gauthier@geosiris.com".to_string(),
            },
            supported_compression: vec![],
            supported_encodings: vec![],
            supported_formats: vec!["xml".to_string()],
            supported_data_objects: vec![],
            supported_protocols: vec![],
            endpoint_capabilities: ma,
        }),
        Box::new(MyHandler {}),
    );
    return connection;
}
