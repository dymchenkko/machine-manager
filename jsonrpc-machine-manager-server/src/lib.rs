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
use tonic::{Request, Response, Status};

pub const CARTESI_BIN_PATH: &str = "CARTESI_BIN_PATH";
pub const CARTESI_IMAGE_PATH: &str = "CARTESI_IMAGE_PATH";

/// Service that implements Machine Manager grpc api
pub struct MachineManagerService {
    pub session_manager: Arc<Mutex<dyn SessionManager>>,
    pub shutting_down: bool,
}

impl MachineManagerService {
    pub fn new(session_manager: Arc<Mutex<dyn SessionManager>>) -> Self {
        MachineManagerService {
            session_manager,
            shutting_down: false,
        }
    }
    /// Check if session current request is same as pending request and return error.
    /// Otherwise, set pending request as current request
    pub fn check_and_set_new_request(
        session: &mut MutexGuard<Session>,
        request_info: &SessionRequest,
    ) -> Result<(), Status> {
        if let Some(current_request) = session.get_current_request() {
            if current_request == request_info {
                log::debug!(
                    "session id={} got same operation request, operation already in progress",
                    &request_info.id
                );
                Err(tonic::Status::already_exists(
                    "operation already in progress",
                ))
            } else {
                // todo review behaviour
                // Do nothing, call will hang on mutex waiting to be executed
                Ok(())
            }
        } else {
            // No request is currently processed, set pending request as current
            log::debug!("session id={} no request is currently processed, set pending request of type {} as current", &request_info.id, &request_info.r#type);
            session.set_current_request(request_info);
            Ok(())
        }
    }

    /// If error string matches pattern, deduce tonic error type to be invalid argument. Otherwise,
    /// resulting type is internal error
    pub fn deduce_tonic_error_type(error_str: &str, pattern: &str, message: &str) -> Status {
        return if let Some(_) = error_str.find(pattern) {
            tonic::Status::invalid_argument(message)
        } else {
            tonic::Status::internal(message)
        };
    }

    /// Handling of the pending session run job request, depending on the current session job execution status.
    pub async fn check_and_set_run_request(
        session_mut: Arc<Mutex<Session>>,
        request_info: &SessionRequest,
    ) -> Result<Option<Response<SessionRunResponse>>, Status> {
        let mut session = session_mut.lock().await;
        if let Some(current_request) = session.get_current_request() {
            if current_request == request_info {
                // Request is the same as session current request, return progress or result
                match session.get_job_progress(&request_info.id).await {
                    Ok((progress, hashes, summaries)) => {
                        let response;
                        if progress.halted && progress.progress < 100 {
                            //Machine halted before reaching the final requested cycle
                            response = SessionRunResponse {
                                run_oneof: Some(cartesi_jsonrpc_interfaces::session_run_response::RunOneof::Result(SessionRunResult {
                                    hashes: hashes,
                                    summaries
                                })),
                            };
                            MachineManagerService::clear_request(&mut session);
                        } else if progress.progress < 100 {
                            response = SessionRunResponse {
                                run_oneof: Some(cartesi_jsonrpc_interfaces::session_run_response::RunOneof::Progress(SessionRunProgress {
                                    cycle: progress.cycle,
                                    ucycle: 0,
                                    progress: progress.progress,
                                    updated_at: progress.updated_at,
                                    application_progress: progress.application_progress,
                                })),
                            };
                        } else {
                            response = SessionRunResponse {
                                run_oneof: Some(cartesi_jsonrpc_interfaces::session_run_response::RunOneof::Result(SessionRunResult {
                                    hashes: hashes,
                                    summaries
                                })),
                            };
                            MachineManagerService::clear_request(&mut session);
                        }
                        Ok(Some(Response::new(response)))
                    }
                    Err(err) => {
                        let error_msg =
                            format!("unable to get execution progress: {}", err.to_string());
                        log::error!("{}", &error_msg);
                        return Err(tonic::Status::invalid_argument(&error_msg));
                    }
                }
            } else {
                // New request different then currently processed request, abort
                // current request and set pending request as current
                log::debug!(
                    "abort current run task for session {}, starting new job",
                    session.get_id()
                );
                MachineManagerService::clear_request(&mut session);
                session.set_current_request(request_info);
                Ok(None)
            }
        } else {
            // No request is currently processed, set pending request as current
            log::debug!("no request is currently processed, set pending request as current");
            session.set_current_request(request_info);
            Ok(None)
        }
    }

    /// Helper function to clear current request of the session
    pub fn clear_request(session: &mut MutexGuard<Session>) {
        session.clear_job();
        session.clear_request();
    }

    /// Helper function to find session by id in session manager. If not found
    /// return invalid argument error
    pub async fn find_session(&self, session_id: &str) -> Result<Arc<Mutex<Session>>, Status> {
        match self
            .session_manager
            .lock()
            .await
            .get_session(session_id)
            .await
        {
            Ok(session_mut) => Ok(Arc::clone(&session_mut)),
            Err(_err) => {
                return Err(tonic::Status::invalid_argument(format!(
                    "unknown session id {}",
                    session_id
                )));
            }
        }
    }

    pub async fn shutting_down(&self) -> bool {
        self.session_manager.lock().await.get_shutting_down_state()
    }
}

async fn new_session_implementation(
    machine_manager_service: &MachineManagerService,
    machine_config: jsonrpc_cartesi_machine::MachineConfig,
    machine_runtime_config: jsonrpc_cartesi_machine::MachineRuntimeConfig,
) -> jsonrpc_core::Result<()> {
    if machine_manager_service.shutting_down().await {
        let error_message = String::from("Server is shutting down, not accepting new requests");
        return Err(jsonrpc_core::Error {
            code: jsonrpc_core::ErrorCode::InternalError,
            message: error_message,
            data: None,
        });
    }

    log::info!("session received new session request");

    log::info!("New session request info");
    //let mut machine_config: cartesi_jsonrpc_interfaces::index::MachineConfig = Default::default();
    //let mut machine_runtime_config: cartesi_jsonrpc_interfaces::index::MachineRuntimeConfig = Default::default();

    //machine_config = serde_json::from_value(arr[0].clone()).unwrap();
    //machine_runtime_config = serde_json::from_value(arr[1].clone()).unwrap();

    //let config = machine_config.clone();
    //log::info!("creating session id from configuration {:#?}", &config);

    let machine_config = &jsonrpc_cartesi_machine::MachineConfig::from(machine_config.clone());
    let machine_runtime_config =
        &jsonrpc_cartesi_machine::MachineRuntimeConfig::from(machine_runtime_config);
    Ok(())

    //let mut session_manager = current.session_manager.lock().await;
    /*match session_manager
        .create_session_from_config(&machine_config, &machine_runtime_config)
        .await
    {
        Ok(_session) => {
            Ok(())
        },
        Err(err) => {
            return Err(jsonrpc_core::Error {
                code: jsonrpc_core::ErrorCode::InternalError,
                message: err.to_string(),
                data: None,
            });
        }
    }*/
}

/// Implementation of the MachineManager service Protobuf API
#[tonic::async_trait]
impl crate::machine_manager_server::JsonRpcMachineManager for MachineManagerService {
    /// Implementation of rpc NewSession (NewSessionRequest) returns (CartesiMachine.Hash)
    fn new_session(
        &self,
        machine_config: jsonrpc_cartesi_machine::MachineConfig,
        machine_runtime_config: jsonrpc_cartesi_machine::MachineRuntimeConfig,
    ) -> jsonrpc_core::BoxFuture<jsonrpc_core::Result<()>> {
        new_session_implementation(self, machine_config, machine_runtime_config).boxed()
    }
    /*
    /// Implementation of rpc SessionRun (SessionRunRequest) returns (SessionRunResponse)
    async fn session_run(
        &self,
        request: Request<SessionRunRequest>,
    ) -> Result<Response<SessionRunResponse>, Status> {

        /*if self.shutting_down().await{
            let error_message = String::from("Server is shutting down, not accepting new requests");
            return Err(tonic::Status::unavailable(error_message));
        }

        let request_info = SessionRequest::from(&request);
        let run_request = request.into_inner();
        log::info!(
            "session id={} received session run request, final_cycles={:?}",
            &run_request.session_id,
            &run_request.final_cycles
        );
        let session_mut = self.find_session(&run_request.session_id).await?;
        if run_request.final_cycles.is_empty() {
            let error_message = format!(
                "session id={} error running session - empty list of final cycles",
                &run_request.session_id
            );
            log::error!("{}", &error_message);
            return Err(tonic::Status::invalid_argument(error_message));
        }
        // Check if we got same run request and should return progress/result
        match MachineManagerService::check_and_set_run_request(
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
        };
        // Start new run job
        let run_result = match Session::run(
            Arc::clone(&session_mut),
            &request_info.id,
            &run_request.final_cycles,
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
        }*/
        Ok(Response::new(SessionRunResponse::default()))

    }

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
}

pub mod machine_manager_server {

    use jsonrpc_core::{BoxFuture, Result};
    use jsonrpc_core::{Id, Params, Success, Version};
    use jsonrpc_derive::rpc;
    use tonic::codegen::*;

    #[rpc(server)]
    pub trait JsonRpcMachineManager {
        #[rpc(name = "machine.machine.config")]
        fn new_session(
            &self,
            machine_config: jsonrpc_cartesi_machine::MachineConfig,
            machine_runtime_config: jsonrpc_cartesi_machine::MachineRuntimeConfig,
        ) -> BoxFuture<Result<()>>;
    }

    /// Generated trait containing gRPC methods that should be implemented for use with MachineManagerServer.

    #[async_trait]
    pub trait MachineManager: Send + Sync + 'static {
        async fn new_session(
            &self,
            machine_config: &jsonrpc_cartesi_machine::MachineConfig,
            machine_runtime_config: &jsonrpc_cartesi_machine::MachineRuntimeConfig,
        ) -> jsonrpc_core::Result<()>;
        /*async fn session_run(
            &self,
            request: tonic::Request<super::SessionRunRequest>,
        ) -> Result<tonic::Response<super::SessionRunResponse>, tonic::Status>;
        async fn session_step(
            &self,
            request: tonic::Request<super::SessionStepRequest>,
        ) -> Result<tonic::Response<super::SessionStepResponse>, tonic::Status>;
        async fn session_store(
            &self,
            request: tonic::Request<super::SessionStoreRequest>,
        ) -> Result<tonic::Response<()>, tonic::Status>;
        async fn session_read_memory(
            &self,
            request: tonic::Request<super::SessionReadMemoryRequest>,
        ) -> Result<tonic::Response<super::SessionReadMemoryResponse>, tonic::Status>;
        async fn session_write_memory(
            &self,
            request: tonic::Request<super::SessionWriteMemoryRequest>,
        ) -> Result<tonic::Response<()>, tonic::Status>;
        async fn session_replace_memory_range(
            &self,
            request: tonic::Request<super::SessionReplaceMemoryRangeRequest>,
        ) -> Result<tonic::Response<()>, tonic::Status>;
        async fn session_get_proof(
            &self,
            request: tonic::Request<super::SessionGetProofRequest>,
        ) -> Result<tonic::Response<crate::Proof>, tonic::Status>;
        async fn end_session(
            &self,
            request: tonic::Request<super::EndSessionRequest>,
        ) -> Result<tonic::Response<()>, tonic::Status>;*/
    }

    #[derive(Debug)]
    pub struct MachineManagerServer<T: JsonRpcMachineManager> {
        inner: _Inner<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
    }
    struct _Inner<T>(Arc<T>);

    impl<T: JsonRpcMachineManager> MachineManagerServer<T> {
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        // Enable decompressing requests with the given encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Compress responses with the given encoding, if the client supports it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
    }

    impl<T: JsonRpcMachineManager> Clone for MachineManagerServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: JsonRpcMachineManager> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: JsonRpcMachineManager> tonic::server::NamedService for MachineManagerServer<T> {
        const NAME: &'static str = "CartesiMachineManager.MachineManager";
    }
}
