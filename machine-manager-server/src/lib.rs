// Copyright (C) 2021 Cartesi Pte. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use
// this file except in compliance with the License. You may obtain a copy of the
// License at http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

//! Implementation of the Machine Mananer service api and
//! Check in service api, defined in machine-manager.proto and
//! cartesi-machine-checkin.proto

pub mod server_manager;
pub mod session;
pub mod session_manager;

use crate::server_manager::ServerManager;
use crate::session::Session;
use crate::session_manager::SessionManager;

use async_mutex::{Mutex, MutexGuard};
use cartesi_jsonrpc_interfaces::index::Proof;
use futures_util::FutureExt;
use jsonrpc_cartesi_machine::MerkleTreeProof;
//use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine_manager::session_run_response::RunOneof;
use cartesi_jsonrpc_interfaces::{
    EndSessionRequest, NewSessionRequest, SessionGetProofRequest, SessionReadMemoryRequest,
    SessionReadMemoryResponse, SessionReplaceMemoryRangeRequest, SessionRunProgress,
    SessionRunRequest, SessionRunResponse, SessionRunResult, SessionStepRequest,
    SessionStepResponse, SessionStoreRequest, SessionWriteMemoryRequest,
};
use session::SessionRequest;
use std::sync::Arc;

pub const CARTESI_BIN_PATH: &str = "CARTESI_BIN_PATH";
pub const CARTESI_IMAGE_PATH: &str = "CARTESI_IMAGE_PATH";

pub struct MachineService {
    pub shutting_down: bool,
    pub session_client: Arc<Mutex<crate::server_manager::CartesiSessionMachineClient>>,
    pub session_manager: Arc<Mutex<dyn SessionManager>>,

}

impl MachineService {
    pub async fn new(shutting_down: bool, address: &str, session_manager: Arc<Mutex<dyn SessionManager>>) -> Self {
        let mut machine_client = crate::server_manager::CartesiSessionMachineClient::default();
        machine_client.connect_to_server(address).await.unwrap();

        MachineService {
            shutting_down,
            session_client: Arc::new(Mutex::new(machine_client)),
            session_manager
        }
    }
}
use jsonrpsee::core::{async_trait, RpcResult};

#[tonic::async_trait]
impl crate::machine_manager_server::JsonRpcMachineServer for MachineService {
    /// Implementation of rpc NewSession (NewSessionRequest) returns (CartesiMachine.Hash)
    async fn machine_machine_config(
        &self,
        machine_config: cartesi_jsonrpc_interfaces::index::MachineConfig,
        machine_runtime_config: cartesi_jsonrpc_interfaces::index::MachineRuntimeConfig,
    ) -> RpcResult<bool> {
        log::info!("machine config");
        let jsonrpc_cartesi_machine = &self.session_client.lock().await;
        let jsonrpc_cartesi_machine = jsonrpc_cartesi_machine
            .cartesi_machine_client
            .as_ref()
            .unwrap();

        log::info!("machine config before: {:?}", machine_config);
        log::info!("machine machine_runtime_config before: {:?}", machine_runtime_config);

        let machine_config = jsonrpc_cartesi_machine::MachineConfig::from(&machine_config);
        let machine_runtime_config =
            jsonrpc_cartesi_machine::MachineRuntimeConfig::from(&machine_runtime_config);

        log::info!("machine config after: {:?}", machine_config);
        log::info!("machine machine_runtime_config after: {:?}", machine_runtime_config);

        let mut session_manager = self.session_manager.lock().await;
                            match session_manager
                                .create_session_from_config(
                                    "session_id",
                                    &machine_config,
                                    &machine_runtime_config,
                                )
                                .await
                            {
                                Ok(_session) => (),
                                Err(err) => {
                                }
                            }
                            let mut machine_client = crate::server_manager::CartesiSessionMachineClient::default();
                            machine_client.connect_to_server("0.0.0.0:50051").await.unwrap(); //TODO delete this part and rewrite just to run remote machine
        let res = machine_client.cartesi_machine_client.unwrap()
            .create_machine(&machine_config, &machine_runtime_config)
            .await;
        log::info!("machine config result {:?}", res);

        /*if self.shutting_down {
            let error_message = String::from("Server is shutting down, not accepting new requests");
            return Err(tonic::Status::unavailable(error_message));
        }*/
        Ok(true)
    }

    async fn run(&self, limit: u64) -> RpcResult<serde_json::Value> {
        log::info!("machine run");

        // Start new run job

        let res = self
            .session_client
            .lock()
            .await
            .cartesi_machine_client
            .as_ref()
            .unwrap()
            .run(limit)
            .await;

        match res {
            Ok(value) => {
                log::info!("result {:?}", value);
                return Ok(value);
            }
            Err(e) => {
                log::info!("error result {:?}", e);

                return Err(jsonrpsee::types::error::ErrorCode::ServerError(-32700).into())
            },
        }

        /*let run_result = match Session::run_defective(
                    Arc::clone(&session_mut),
                    &request_info.id,
                    &run_request.final_cycles,
                )
                .await
                {
                    Ok(progress) => {
                        //Job started, return initial progress
                        Ok(SessionRunResponse {
                            run_oneof: Some(RunOneof::Progress(progress)),
                        })
                    }
                    Err(err) => Err(err.to_string()),
                };

                match run_result {
                    Ok(response) => {
                        if let Some(RunOneof::Result { .. }) = &response.run_oneof {
                            //Clear current request and job task
                            let mut session = session_mut.lock().await;
                            MachineManagerService::clear_request(&mut session); //Clear current RUN request
                        }
                        log::info!(
                            "session_id='{}' run request processed successfully",
                            &run_request.session_id
                        );
                        Ok(Response::new(response))
                    }
                    Err(err_str) => {
                        //Clear current request and job task
                        let mut session = session_mut.lock().await;
                        MachineManagerService::clear_request(&mut session); //Clear current RUN request
                        log::error!("{}", &err_str);
                        Err(tonic::Status::internal(err_str))
                    }
                }
        */
        return Ok(serde_json::Value::Bool(true));
    }
}
/// Service that implements Machine Manager grpc api
#[derive(Debug)]
pub struct MachineServer<T: crate::machine_manager_server::JsonRpcMachineServer> {
    inner: _Inner<T>,
}
#[derive(Debug)]
struct _Inner<T>(Arc<T>);
impl<T: crate::machine_manager_server::JsonRpcMachineServer> MachineServer<T> {
    pub fn new(inner: T) -> Self {
        Self::from_arc(Arc::new(inner))
    }
    pub fn from_arc(inner: Arc<T>) -> Self {
        let inner = _Inner(inner);
        Self { inner }
    }
}

/// Implementation of the MachineManager service Protobuf API
/*#[tonic::async_trait]
impl <T: crate::machine_manager_server::JsonRpcMachineServer> MachineServer<T>{

    /// Implementation of rpc NewSession (NewSessionRequest) returns (CartesiMachine.Hash)
    async fn machine_machine_config(
        &self,
        machine_config: cartesi_jsonrpc_interfaces::index::MachineConfig,
        machine_runtime_config: cartesi_jsonrpc_interfaces::index::MachineRuntimeConfig,
    ) -> jsonrpsee::core::RpcResult<bool> {
        if self.shutting_down().await {
            return Err(jsonrpsee::types::error::ErrorCode::ServerError(-32000).into());
        }
        log::info!("session received new session request");

        log::info!("New session request info");

        let mut session_manager = self.session_manager.lock().await;
        match session_manager
            .create_session_from_config("session_id", &jsonrpc_cartesi_machine::MachineConfig::from(&machine_config), &jsonrpc_cartesi_machine::MachineRuntimeConfig::from(&machine_runtime_config), false)
            .await
        {
            Ok(_session) => {
                log::info!("New session request info");

                return Ok(true)
            },
            Err(err) => {
                log::info!("Error {:?}", err);

                return Err(jsonrpsee::types::error::ErrorCode::InternalError.into());
            }
        }

    }

    /// Implementation of rpc SessionRun (SessionRunRequest) returns (SessionRunResponse)
    async fn run(
        &self,
        limit: u64,
    ) -> jsonrpsee::core::RpcResult<serde_json::Value> {

        if self.shutting_down().await {
            return Err(jsonrpsee::types::error::ErrorCode::ServerError(-32000).into());
        }

        log::info!(
            "received session run request, limit={:?}", limit
        );
        let session_mut = self.find_session("session_id").await.unwrap();
        /*if run_request.final_cycles.is_empty() {
            let error_message = format!(
                "session id={} error running session - empty list of final cycles",
                &run_request.session_id
            );
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }*/
        // Check if we got same run request and should return progress/result
        /*match MachineManagerService::check_and_set_run_request(
            Arc::clone(&session_mut),
            &request_info,
        )
        .await
        {
            Ok(progress_status) => {
                if let Some(progress) = progress_status {
                    return Ok(progress);
                }
            }
            Err(e) => return Err(e),
        };*/
        // Start new run job
        let run_result = match Session::run(
            Arc::clone(&session_mut),
            "session_id",
            &[limit],
        )
        .await
        {
            Ok(progress) => {
                //Job started, return initial progress
                Ok(SessionRunResponse {
                    run_oneof: Some(cartesi_jsonrpc_interfaces::session_run_response::RunOneof::Progress(progress)),
                })
            }
            Err(err) => Err(err.to_string()),
        };

        match run_result {
            Ok(response) => {
                if let Some(cartesi_jsonrpc_interfaces::session_run_response::RunOneof::Result { .. }) = &response.run_oneof {
                    //Clear current request and job task
                    let mut session = session_mut.lock().await;
                    MachineManagerService::clear_request(&mut session); //Clear current RUN request
                }
                log::info!(
                    "session_id='{}' run request processed successfully",
                    "session_id"
                );
                return Ok(serde_json::Value::Bool(true))
            }
            Err(err_str) => {
                //Clear current request and job task
                let mut session = session_mut.lock().await;
                MachineManagerService::clear_request(&mut session); //Clear current RUN request
                log::error!("{}", &err_str);
                return Err(jsonrpsee::types::error::ErrorCode::InternalError.into())
            }
        }
    }
    */
/*
/// Implementation of rpc SessionStep (SessionStepRequest) returns (SessionStepResponse)
async fn session_step(
    &self,
    request: Request<SessionStepRequest>,
) -> Result<Response<SessionStepResponse>, Status> {

    if self.shutting_down().await{
        let error_message = String::from("Server is shutting down, not accepting new requests");
        return Err(tonic::Status::unavailable(error_message));
    }

    let request_info = SessionRequest::from(&request);
    let step_request = request.into_inner();
    log::info!(
        "session id={} received session step request, initial cycle: {}",
        &step_request.session_id,
        &step_request.initial_cycle
    );
    let session_mut = self.find_session(&step_request.session_id).await?;
    let mut session = session_mut.lock().await;
    match &step_request.step_params_oneof {
        Some(step_params_oneof) => match step_params_oneof {
            cartesi_jsonrpc_interfaces::session_step_request::StepParamsOneof::StepParams(request) => {
                MachineManagerService::check_and_set_new_request(&mut session, &request_info)?;
                if let Some(log_type) = &request.log_type {
                    // Perform step
                    match session
                        .step(
                            step_request.initial_cycle,
                            &jsonrpc_cartesi_machine::AccessLogType::from(log_type),
                            request.one_based,
                        )
                        .await
                    {
                        Ok(log) => {
                            let response = SessionStepResponse {
                                    log: Some(cartesi_jsonrpc_interfaces::index::AccessLog::from(&log))
                                };
                            MachineManagerService::clear_request(&mut session);
                            log::info!(
                                "session id={} step request executed successfully",
                                &step_request.session_id
                            );
                            Ok(Response::new(response))
                        }
                        Err(err) => {
                            MachineManagerService::clear_request(&mut session);
                            let error_message = format!(
                                "error executing session step for session id={}. Details:'{}'",
                                &session.get_id(),
                                err.to_string()
                            );
                            log::error!("{}", &error_message);
                            return Err(MachineManagerService::deduce_tonic_error_type(
                                &err.to_string(),
                                "unexpected session cycle, current cycle is",
                                &error_message,
                            ));
                        }
                    }
                } else {
                    let error_message = "step request invalid argument, missing log type";
                    log::error!("{}", &error_message);
                    return Err(tonic::Status::invalid_argument(error_message));
                }
            }
        },
        None => {
            let error_message = "step request invalid argument, missing step params argument";
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }
    }
}

/// Implementation of rpc SessionStore (SessionStoreRequest) returns (CartesiMachine.Void)
async fn session_store(
    &self,
    request: Request<SessionStoreRequest>,
) -> Result<Response<()>, Status> {
    let request_info = SessionRequest::from(&request);
    let store_request = request.into_inner();
    log::info!(
        "received session store request, session id={}",
        &store_request.session_id
    );
    let session_mut = self.find_session(&store_request.session_id).await?;
    let mut session = session_mut.lock().await;
    match store_request.store {
        Some(st_req) => {
            MachineManagerService::check_and_set_new_request(&mut session, &request_info)?;
            match session.store(&st_req.directory).await {
                Ok(_) => (),
                Err(err) => {
                    MachineManagerService::clear_request(&mut session);
                    let error_message = err.to_string();
                    log::error!("{}", &error_message);
                    return Err(tonic::Status::internal(error_message));
                }
            }
        }
        None => {
            let error_message =
                "error execution session store request - missing store directory argument";
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }
    }
    MachineManagerService::clear_request(&mut session);
    log::info!(
        "session id={} store request executed successfully",
        &store_request.session_id
    );
    Ok(Response::new(()))
}

/// Implementation of rpc SessionReadMemory (SessionReadMemoryRequest) returns (SessionReadMemoryResponse)
async fn session_read_memory(
    &self,
    request: Request<SessionReadMemoryRequest>,
) -> Result<Response<SessionReadMemoryResponse>, Status> {
    let request_info = SessionRequest::from(&request);
    let read_request = request.into_inner();
    log::info!(
        "received read memory request, session id={}, cycle: {}",
        &read_request.session_id,
        &read_request.cycle
    );
    let session_mut = self.find_session(&read_request.session_id).await?;
    let mut session = session_mut.lock().await;
    match &read_request.position {
        Some(position) => {
            log::debug!(
                "executing read memory request for session {}, cycle: {} address {} length {}",
                &read_request.session_id,
                &read_request.cycle,
                &position.address,
                &position.length
            );
            MachineManagerService::check_and_set_new_request(&mut session, &request_info)?;
            match session
                .read_mem(read_request.cycle, position.address, position.length)
                .await
            {
                Ok(data) => {
                    let response = SessionReadMemoryResponse{
                        read_content: Some(cartesi_jsonrpc_interfaces::ReadMemoryResponse{
                            data
                        })
                    };
                    MachineManagerService::clear_request(&mut session);
                    log::info!(
                        "session id={} read memory request executed successfully",
                        &read_request.session_id
                    );
                    Ok(Response::new(response))
                }
                Err(err) => {
                    MachineManagerService::clear_request(&mut session);
                    let error_message = format!(
                        "error executing session read memory for session id={}. Details:'{}'",
                        &session.get_id(),
                        err.to_string()
                    );
                    log::error!("{}", &error_message);
                    return Err(MachineManagerService::deduce_tonic_error_type(
                        &err.to_string(),
                        "unexpected session cycle, current cycle is",
                        &error_message,
                    ));
                }
            }
        }
        None => {
            let error_message =
                "error executing session read memory request - missing position argument";
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }
    }
}

/// Implementation of rpc SessionWriteMemory (SessionWriteMemoryRequest) returns (CartesiMachine.Void)
async fn session_write_memory(
    &self,
    request: Request<SessionWriteMemoryRequest>,
) -> Result<Response<()>, Status> {
    let request_info = SessionRequest::from(&request);
    let write_request = request.into_inner();
    log::info!(
        "received session write memory request, session id={}, cycle={}",
        &write_request.session_id,
        &write_request.cycle
    );
    let session_mut = self.find_session(&write_request.session_id).await?;
    let mut session = session_mut.lock().await;
    match write_request.position {
        Some(position) => {
            MachineManagerService::check_and_set_new_request(&mut session, &request_info)?;
            let mut pos_data = base64::encode(position.data);
            if pos_data.ends_with("=") {
                pos_data.push('\n');

            }
            match session
                .write_mem(write_request.cycle, position.address, pos_data)
                .await
            {
                Ok(()) => {
                    MachineManagerService::clear_request(&mut session);
                    log::info!(
                        "session id={} write memory request executed successfully",
                        &write_request.session_id
                    );
                    Ok(Response::new(()))
                }
                Err(err) => {
                    MachineManagerService::clear_request(&mut session);
                    let error_message = format!(
                        "Error executing session write memory for session id={}. Details:'{}'",
                        &session.get_id(),
                        err.to_string()
                    );
                    log::error!("{}", &error_message);
                    return Err(MachineManagerService::deduce_tonic_error_type(
                        &err.to_string(),
                        "unexpected session cycle, current cycle is",
                        &error_message,
                    ));
                }
            }
        }
        None => {
            let error_message =
                "Error executing session write memory request - missing position argument";
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }
    }
}

async fn session_replace_memory_range(
    &self,
    request: Request<SessionReplaceMemoryRangeRequest>,
) -> Result<Response<()>, Status> {
    let request_info = SessionRequest::from(&request);
    let replace_request = request.into_inner();
    log::info!(
        "received session replace memory range request, session id={}, cycle={}",
        &replace_request.session_id,
        &replace_request.cycle
    );
    let session_mut = self.find_session(&replace_request.session_id).await?;
    let mut session = session_mut.lock().await;
    match replace_request.range {
         Some(range) => {
           MachineManagerService::check_and_set_new_request(&mut session, &request_info)?;

          match session
          .replace_memory_range(replace_request.cycle, &range)
                .await
            {
                Ok(()) => {
                    MachineManagerService::clear_request(&mut session);
                    log::info!(
                        "session id={} replace memory range request executed successfully",
                        &replace_request.session_id
                    );
                    Ok(Response::new(()))
                }
                Err(err) => {
                    MachineManagerService::clear_request(&mut session);
                    let error_message = format!(
                        "Error executing session replace memory range for session id={}. Details:'{}'",
                        &session.get_id(),
                        err.to_string()
                    );
                    log::error!("{}", &error_message);
                    return Err(MachineManagerService::deduce_tonic_error_type(
                        &err.to_string(),
                        "unexpected session cycle, current cycle is",
                        &error_message,
                    ));
                }
            }
        }
        None => {
            let error_message =
                "Error executing session replac memory range request - missing range argument";
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }
    }
}

/// Implementation of rpc SessionGetProof (SessionGetProofRequest) returns (CartesiMachine.MerkleTreeProof)
async fn session_get_proof(
    &self,
    request: Request<SessionGetProofRequest>,
) -> Result<Response<Proof>, Status> {
    let request_info = SessionRequest::from(&request);
    let proof_request = request.into_inner();
    log::info!(
        "received session get proof request, session id={}, cycle={}",
        &proof_request.session_id,
        &proof_request.cycle
    );

    let session_mut = self.find_session(&proof_request.session_id).await?;
    let mut session = session_mut.lock().await;
    match proof_request.target {
        Some(target) => {
            MachineManagerService::check_and_set_new_request(&mut session, &request_info)?;
            match session
                .get_proof(proof_request.cycle, target.address, target.log2_size)
                .await
            {
                Ok(result) => {
                    MachineManagerService::clear_request(&mut session);
                    log::info!(
                        "session id={} get proof request executed successfully",
                        &proof_request.session_id
                    );
                    Ok(Response::new(Proof::from(&result)))
                }
                Err(err) => {
                    MachineManagerService::clear_request(&mut session);
                    let error_message = &format!(
                        "error executing session get proof for session id={}. Details:'{}'",
                        &session.get_id(),
                        err.to_string()
                    );
                    log::error!("{}", &error_message);
                    return Err(MachineManagerService::deduce_tonic_error_type(
                        &err.to_string(),
                        "unexpected session cycle, current cycle is",
                        &error_message,
                    ));
                }
            }
        }
        None => {
            let error_message =
                "error executing session get proof request - missing target argument";
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }
    }
}

/// Implementation of rpc EndSession (EndSessionRequest) returns (CartesiMachine.Void)
async fn end_session(
    &self,
    request: Request<EndSessionRequest>,
) -> Result<Response<()>, Status> {
    let end_request = request.into_inner();
    log::info!(
        "received end session request, session id={}",
        &end_request.session_id
    );
    let mut session_manager = self.session_manager.lock().await;
    match session_manager.close_session(&end_request.session_id).await {
        Ok(()) => {
            log::info!(
                "end session id={} request executed successfully",
                &end_request.session_id
            );
            Ok(Response::new(()))
        }
        Err(err) => {
            let error_message = format!(
                "Error ending session id={}. Details: '{}'",
                &end_request.session_id,
                err.to_string()
            );
            log::error!("{}", &error_message);
            return Err(tonic::Status::internal(error_message));
        }
    }
}*/
//}
pub mod machine_manager_server {

    use jsonrpsee::core::{async_trait, RpcResult};
    use jsonrpsee::proc_macros::rpc;
    #[rpc(server)]
    pub trait JsonRpcMachine: Send + Sync + 'static {
        #[method(name = "machine.machine.config")]
        async fn machine_machine_config(
            &self,
            machine_config: cartesi_jsonrpc_interfaces::index::MachineConfig,
            machine_runtime_config: cartesi_jsonrpc_interfaces::index::MachineRuntimeConfig,
        ) -> RpcResult<bool>;

        #[method(name = "machine.run")]
        async fn run(&self, limit: u64) -> RpcResult<serde_json::Value>;
    }
}
