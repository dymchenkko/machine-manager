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

//! Session implementation

use super::server_manager::CartesiSessionMachineClient;
use async_mutex::Mutex;
use std::sync::Arc;

use crate::server_manager::ServerManager;
use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine::{Csr, RunResponse};
use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine_manager::SessionRunProgress;
use generic_array::GenericArray;
use grpc_cartesi_machine::{
    GrpcCartesiMachineClient, MachineConfig, MachineRuntimeConfig, MerkleTreeProof, MemoryRangeConfig
};
use sha3::{Digest, Sha3_256};
use std::fmt::Debug;
use tonic::IntoRequest;

pub const WAIT_SLEEP_STEP: u64 = 100; //ms
pub const WAIT_RETRIES_NUMBER: u64 = 200; // in total wait for check in 20s
const RUN_STEP: u64 = 10_000_000; //Number of running cycles to run with one call to Cartesi emulator
const RUN_STEPS_AT_ONCE: i32 = 10; //Number of steps to run at once in batch
const MAX_CYCLE: u64 = 15;

#[derive(Debug, Default)]
/// Error type returned from session functions
struct CartesiSessionError {
    message: String,
}

impl CartesiSessionError {
    fn new(message: &str) -> Self {
        CartesiSessionError {
            message: String::from(message),
        }
    }
}

impl std::fmt::Display for CartesiSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "machine manager session error: {}", &self.message)
    }
}

impl std::error::Error for CartesiSessionError {}

/// Session could be in the one of the following states. It starts with New,
/// it is active when machine moves from 0 cycle, and Halted
/// when machine halts on execution
#[derive(Clone, Debug, PartialEq)]
enum SessionState {
    New,
    Active,
    Halted(u64),
    Closed,
}

/// Progress of the run job execution
#[derive(Clone, Debug, Copy)]
pub struct ExecutionProgress {
    pub progress: u64,
    pub application_progress: u64,
    pub updated_at: u64,
    pub cycle: u64,
    pub halted: bool,
}

impl ExecutionProgress {
    fn new() -> ExecutionProgress {
        ExecutionProgress {
            progress: 0,
            application_progress: 0,
            updated_at: chrono::Utc::now().timestamp() as u64,
            cycle: 0,
            halted: false,
        }
    }
}

/// Summary of the external machine manager client request
#[derive(Debug, Default, Clone)]
pub struct SessionRequest {
    pub id: String,
    pub r#type: String,
    pub message: String,
}

/// To generate unique request id, calculate it by hashing request message
fn calculate_request_id(
    tonic_request_msg: &str,
) -> GenericArray<u8, <Sha3_256 as Digest>::OutputSize> {
    let mut hasher = Sha3_256::new();
    hasher.update(tonic_request_msg);
    hasher.finalize()
}

impl<T> From<&tonic::Request<T>> for SessionRequest
where
    T: Debug,
{
    fn from(tonic_request: &tonic::Request<T>) -> Self {
        let hash_id = calculate_request_id(&format!("{:?}", tonic_request));
        SessionRequest {
            id: format!("{:?}", hash_id),
            r#type: std::any::type_name::<T>().to_string(),
            message: format!("{:?}", tonic_request.into_request()),
        }
    }
}

impl PartialEq for SessionRequest {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.r#type == other.r#type
    }
}

/// Details of the run job (task) that is executed in session
#[allow(dead_code)]
struct RunTask {
    /// Id if the task
    id: String,
    /// Id of the client request
    request_id: String,
    /// Final cycles of the run task
    final_cycles: Vec<u64>,
    /// Current progress
    progress: ExecutionProgress,
    /// Hashes of the machine when it reaches final cycles
    hashes: Vec<grpc_cartesi_machine::Hash>,
    /// Summaries as RunResponse in the final cycles
    summaries: Vec<RunResponse>,
}

impl RunTask {
    fn new(request_id: &str, final_cycles: &[u64]) -> Self {
        RunTask {
            id: format!("{:?}", final_cycles),
            request_id: request_id.to_string(),
            final_cycles: Vec::from(final_cycles),
            progress: ExecutionProgress::new(),
            hashes: Vec::new(),
            summaries: Vec::new(),
        }
    }
}

/// Job structure comprises of task and handle
/// to the thread that is executing task
#[allow(dead_code)]
struct Job {
    job_task: Arc<Mutex<RunTask>>,
    job_handle: Option<std::thread::JoinHandle<()>>,
}

/// Session structure. Keeps all relevant details about the session
pub struct Session {
    /// Session id
    id: String,
    /// Client to the remove remote-cartesi-machine
    cartesi_session_client: CartesiSessionMachineClient,
    /// Handle to the server manager
    server_manager: Arc<Mutex<dyn ServerManager>>,
    /// Current session state
    state: SessionState,
    /// Current session cycle
    cycle: u64,
    /// Last performed snapshot cycle is on cycle snapshot_cycle
    snapshot_cycle: Option<u64>,
    /// Machine configuration used to create Cartesi server machine
    machine_config: Option<Arc<MachineConfig>>,
    /// Path to storage folder from which machine should be loaded
    directory: Option<String>,
    /// Runtime configuration
    machine_runtime_config: Arc<MachineRuntimeConfig>,
    /// Original request that is currently executed
    current_request: Option<SessionRequest>,
    /// Currently executed job
    current_job: Option<Job>,
}

impl Session {
    /// Instantiate server using server manager and set Cartesi
    /// session client handle
    
    pub fn cartesi_session_client (&self) -> CartesiSessionMachineClient{
        self.cartesi_session_client.clone()
    }
    pub async fn setup_session_cartesi_server(
        &mut self,
        checkin_address: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Start Cartesi machine server for this session
        let cartesi_session_machine_client = match self
            .server_manager
            .lock()
            .await
            .instantiate_server(&self.id, checkin_address)
            .await
        {
            Ok(client) => client,
            Err(err) => {
                return Err(Box::new(CartesiSessionError::new(&format!(
                    "unable to instantiate server - {}",
                    err.to_string()
                ))))
            }
        };
        self.cartesi_session_client = cartesi_session_machine_client;
        Ok(())
    }

    /// Remove Cartesi machine client, effectively disconnecting from
    /// Cartesi machine server
    fn disconnect(&mut self) {
        self.cartesi_session_client.cartesi_machine_client = None;
    }

    /// Retrieve session id
    pub fn get_id(&self) -> &str {
        &self.id
    }

    pub fn get_server_manager(&self) -> &Arc<Mutex<dyn ServerManager>> {
        &self.server_manager
    }

    /// Check if there is an active Cartesi machine client connection to
    /// Cartesi emulator server
    pub fn is_connected(&self) -> bool {
        self.cartesi_session_client.cartesi_machine_client.is_some()
    }

    /// Setup connection to Cartesi emulator machine server using
    /// remote-cartesi-machine check in info kept in server manager
    pub async fn setup_connection(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut server_manager = self.server_manager.lock().await;
        let (status, address) = server_manager.get_check_in_status(&self.id);
        if status {
            self.cartesi_session_client
                .connect_to_server(&address)
                .await?;
            let addr_info: std::net::SocketAddr = address.parse()?;
            self.cartesi_session_client.port = addr_info.port() as u32;
            self.cartesi_session_client.server_host = addr_info.ip().to_string();
            Ok(())
        } else {
            Err(Box::new(CartesiSessionError::new(
                "unable to setup session client, server is not checked in",
            )))
        }
    }

    /// Get current client request processed in session
    pub fn get_current_request(&self) -> &Option<SessionRequest> {
        &self.current_request
    }

    /// Set new active client request
    pub fn set_current_request(&mut self, new_request: &SessionRequest) {
        self.current_request = Some(new_request.clone());
    }

    /// Clear active client request
    pub fn clear_request(&mut self) {
        self.current_request = None;
    }

    /// Get execution progress of the run job currently processed
    pub async fn get_job_progress(
        &self,
        request_id: &str,
    ) -> Result<
        (
            ExecutionProgress,
            Vec<grpc_cartesi_machine::Hash>,
            Vec<RunResponse>,
        ),
        Box<dyn std::error::Error>,
    > {
        if let Some(current_job) = &self.current_job {
            let current_task = current_job.job_task.lock().await;
            if current_task.request_id != request_id {
                return Err(Box::new(CartesiSessionError::new(&format!(
                    "requesting progress for task id='{}', current task id='{}'",
                    request_id, current_task.request_id
                ))));
            }
            Ok((
                current_task.progress,
                current_task.hashes.clone(),
                current_task.summaries.clone(),
            ))
        } else {
            Err(Box::new(CartesiSessionError::new(
                "no current task is running",
            )))
        }
    }

    /// Clear current run job
    pub fn clear_job(&mut self) {
        if let Some(_job) = self.current_job.take() {
            //Do nothing, current_job is replaced with empty
        };
        self.current_job = None;
    }

    /// Create new session object from provided machine configuration
    /// and runtime machine configuration. Resulting session is in initial state.
    pub async fn init_from_config(
        server_manager: &Arc<Mutex<dyn ServerManager>>,
        session_id: &str,
        config: &MachineConfig,
        runtime_config: &MachineRuntimeConfig,
        request: &SessionRequest,
    ) -> Result<Session, Box<dyn std::error::Error>> {
        let server_manager = Arc::clone(server_manager);
        // Create new session
        let ret = Session {
            id: session_id.to_string(),
            cartesi_session_client: CartesiSessionMachineClient::default(),
            current_request: Some(request.clone()),
            state: SessionState::New,
            machine_config: Some(Arc::new(config.clone())),
            directory: None,
            machine_runtime_config: Arc::new(runtime_config.clone()),
            server_manager,
            cycle: 0,
            snapshot_cycle: None,
            current_job: None,
        };
        Ok(ret)
    }

    /// Create new session object from provided directory
    /// and runtime machine configuration. Resulting session is in initial state.
    pub async fn init_from_directory(
        server_manager: &Arc<Mutex<dyn ServerManager>>,
        session_id: &str,
        directory: &str,
        runtime_config: &MachineRuntimeConfig,
        request: &SessionRequest,
    ) -> Result<Session, Box<dyn std::error::Error>> {
        let server_manager = Arc::clone(server_manager);
        // Create new session
        let ret = Session {
            id: session_id.to_string(),
            cartesi_session_client: Default::default(),
            current_request: Some(request.clone()),
            state: SessionState::New,
            machine_config: None,
            directory: Some(directory.to_string()),
            machine_runtime_config: Arc::new(runtime_config.clone()),
            server_manager,
            cycle: 0,
            snapshot_cycle: None,
            current_job: None,
        };

        Ok(ret)
    }

    /// Retrieve internal client to Cartesi machine emulator server
    fn get_cartesi_machine_client(
        &mut self,
    ) -> Result<&mut GrpcCartesiMachineClient, Box<dyn std::error::Error>> {
        match &mut self.cartesi_session_client.cartesi_machine_client {
            Some(client) => Ok(client),
            None => Err(Box::new(CartesiSessionError::new(
                "cartesi machine client not connected or available",
            ))),
        }
    }

    /// Create new machine instance on remote Cartesi machine emulator server
    pub async fn create_machine(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let machine_runtime_config = Arc::clone(&self.machine_runtime_config);
        if let Some(machine_config) = &self.machine_config {
            let machine_config = Arc::clone(machine_config);
            let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
            grpc_cartesi_machine
                .create_machine(&*machine_config, &*machine_runtime_config)
                .await?;
            self.cycle = 0;
            self.snapshot_cycle = None;
            self.state = SessionState::New;
            Ok(())
        } else if let Some(directory) = &self.directory {
            let dir_p = directory.clone();
            //must call it as unsafe as self is already borrowed, but it is legal
            let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
            grpc_cartesi_machine
                .load_machine(&*dir_p, &*machine_runtime_config)
                .await?;
            self.cycle = 0;
            self.snapshot_cycle = None;
            self.state = SessionState::New;
            Ok(())
        } else {
            Err(Box::new(CartesiSessionError::new(
                "could not recreate machine, missing machine configuration or directory",
            )))
        }
    }

    /// Retrieve current root hash of machine instance on remote Cartesi machine emulator server
    pub async fn get_root_hash(
        &mut self,
    ) -> Result<grpc_cartesi_machine::Hash, Box<dyn std::error::Error>> {
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        grpc_cartesi_machine.get_root_hash().await
    }

    /// Run session machine instance one CPU step forward. Functon
    /// is for internal session usage
    async fn run_step(
        &mut self,
        final_cycle: u64,
    ) -> Result<RunResponse, Box<dyn std::error::Error>> {
        if final_cycle < self.cycle {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "machine is already at cycle {}, requested cycle {}",
                self.cycle, final_cycle
            ))));
        }
        // Perform running in steps of RUN_STEP cycles
        let mut result = Default::default();
        for _current_step in 1..=RUN_STEPS_AT_ONCE {
            let step = if final_cycle > self.cycle + RUN_STEP {
                self.cycle + RUN_STEP
            } else {
                final_cycle
            };
            {
                log::debug!("running session id=\"{}\" to cycle {}", &self.id, step);
                let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
                result = grpc_cartesi_machine.run(step).await?;
            }
            self.cycle = result.mcycle;
            // Check if machine instance is halted and set session state flag accordingly
            if result.iflags_h {
                self.state = SessionState::Halted(result.mcycle);
            } else {
                self.state = SessionState::Active;
            }

            if final_cycle == self.cycle || result.iflags_h {
                break;
            }
        }
        Ok(result)
    }

    /// Run machine to a particular cycle. If current cycle is bigger than
    /// requested cycle, return error. Function for internal session usage.
    async fn run_to_cycle(
        &mut self,
        requested_cycle: u64,
    ) -> Result<RunResponse, Box<dyn std::error::Error>> {
        log::debug!(
            "running machine session id {} current cycle/requested cycle {}/{} ->",
            &self.id,
            self.cycle,
            requested_cycle
        );
        if requested_cycle >= self.cycle {
            //Run machine to requested cycle, return final Run response
            loop {
                let result = self.run_step(requested_cycle).await?;
                if result.mcycle == requested_cycle || result.iflags_h {
                    return Ok(result);
                }
            }
        } else {
            Err(Box::new(CartesiSessionError::new(
                "internal execution error, requested cycle is smaller than current cycle",
            )))
        }
    }


    /// Perform snapshot of machine instance on remote Cartesi machine emulator server
    /// On Cartesi machine server snapshot is implemented by forking process, and
    /// child process uses different port for communication. Waiting for check in
    /// and reestablishing connection is part of snapshot procedure
    pub async fn snapshot(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_connected() {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "Can not perform snapshot for session id {}, no connection",
                self.id
            ))));
        }
        // Tell server manager to expect new checking from snapshot
        self.server_manager.lock().await.set_server_check_in_status(
            &self.id,
            false,
            Default::default(),
        );
        // Perform snapshot
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        grpc_cartesi_machine.snapshot().await?;
        self.snapshot_cycle = Some(self.cycle);
        self.disconnect();
        // Wait for the snapshot to check in
        for i in 1..=WAIT_RETRIES_NUMBER {
            log::debug!(
                "waiting for snapshot check in for session_id={} retry={}",
                &self.id,
                i
            );
            std::thread::sleep(std::time::Duration::from_millis(WAIT_SLEEP_STEP));
            let (checked, address) = self
                .server_manager
                .lock()
                .await
                .get_check_in_status(&self.id);
            if checked {
                log::debug!(
                    "session session_id={} snapshot is checked in on address: {}",
                    &self.id,
                    &address
                );
                break;
            }

            if i == WAIT_RETRIES_NUMBER {
                // Kill server process and return error
                self.close().await?;
                return Err(Box::new(CartesiSessionError::new(&format!(
                    "Timeout while waiting for session id={} snapshot to check in",
                    self.id
                ))));
            }
        }
        // Establish connection to child emulator process
        self.setup_connection().await?;
        Ok(())
    }

    /// Perform rollback of machine instance on remote Cartesi machine emulator server
    /// On Cartesi machine server snapshot/roolback is implemented by forking process, and
    /// child process uses different port for communication. Waiting for check in
    /// and reestablishing connection to the parent rollback process is part of snapshot procedure
    pub async fn rollback(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_connected() {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "Can not perform snapshot for session id {}, no connection",
                self.id
            ))));
        }
        //Tell server manager to expect new checking from snapshot
        self.server_manager.lock().await.set_server_check_in_status(
            &self.id,
            false,
            Default::default(),
        );
        //Perform rollback
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        grpc_cartesi_machine.rollback().await?;
        self.cycle = self.snapshot_cycle.unwrap_or_default();
        self.snapshot_cycle = None;
        self.disconnect();
        //Wait for the rollback to check in
        // Possible to remove busy wait with conditional variable
        for i in 1..=WAIT_RETRIES_NUMBER {
            log::debug!(
                "waiting for rollback session check in for session_id={} retry={}",
                &self.id,
                i
            );
            std::thread::sleep(std::time::Duration::from_millis(WAIT_SLEEP_STEP));
            let (checked, address) = self
                .server_manager
                .lock()
                .await
                .get_check_in_status(&self.id);
            if checked {
                log::debug!(
                    "session session_id={} rollback is checked in on address: {}",
                    &self.id,
                    &address
                );
                break;
            }
            if i == WAIT_RETRIES_NUMBER {
                // Kill server process and return error
                self.close().await?;
                return Err(Box::new(CartesiSessionError::new(&format!(
                    "Timeout while waiting for session id={} snapshot to check in",
                    self.id
                ))));
            }
        }
        // Connect to parent process
        self.setup_connection().await?;
        Ok(())
    }

    /// Run machine according to list of final cycles
    ///
    /// # Details
    /// * Perform rollback, run machine to initial cycle
    /// * Perform snapshot
    /// * Spawn background task to run to cycles one by one
    /// * Return initial progress status
    ///
    /// Rollback/Snapshot again is performed if  snapshot_cycle < current session cycle or
    /// current session cycle < first_job_cycle.
    ///
    /// When same run request comes from the user, return current progress
    /// or finished task result. Some additional cases that could happen:
    /// * Only one value in the final cycles list - then just run to that value and return result. No need to span
    /// separate thread to execute job
    /// * If machine halts before requested final cycle, return halted cycle and hash
    pub async fn run(
        session_mut: Arc<Mutex<Session>>,
        request_id: &str,
        final_cycles: &[u64],
    ) -> Result<SessionRunProgress, Box<dyn std::error::Error>> {
        log::debug!("got run request for final cycles {:?}", final_cycles);
        let mut session = session_mut.lock().await;
        if final_cycles.is_empty() {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "run operation invalid final cycles list for session id {}",
                &session.id
            ))));
        }
        let first_job_cycle = final_cycles[0];
        // Check current snapshot cycle, perform snapshot
        // Snapshot must exist to execute run job, one is taken when machine is created
        if let Some(snapshot_cycle) = session.snapshot_cycle {
            if snapshot_cycle <= first_job_cycle {
                let perform_snapshot =
                    snapshot_cycle < session.cycle || session.cycle < first_job_cycle;

                if perform_snapshot {
                    // Perform rollback and run to starting job cycle, then do a snapshot again
                    session.rollback().await?;
                }
                let initial_run_response = session.run_to_cycle(first_job_cycle).await?;
                if initial_run_response.iflags_h {
                    log::warn!("warning: machine in session id=\"{}\" halted while trying to reach initial cycle", &session.id);
                }
                if perform_snapshot {
                    session.snapshot().await?;
                }

                // If there is only one final cycle in the list, already got to it.
                // Prepare result immediately
                if final_cycles.len() == 1 {
                    let current_root_hash = match session.get_root_hash().await {
                        Ok(hash) => hash,
                        Err(err) => {
                            return Err(Box::new(CartesiSessionError::new(&format!(
                                    "error running machine session_id=\"{}\", unable to get root hash on target cycle {}, details:'{}'",
                                    &session.id, first_job_cycle, err.to_string()
                                ))));
                        }
                    };

                    session.current_job = Some(Job {
                        job_task: {
                            let mut new_run_task = RunTask::new(request_id, final_cycles);
                            new_run_task.progress = ExecutionProgress {
                                application_progress: 0,
                                progress: 100,
                                cycle: initial_run_response.mcycle,
                                updated_at: chrono::Utc::now().timestamp() as u64,
                                halted: false,
                            };
                            new_run_task.hashes.push(current_root_hash);
                            new_run_task.summaries.push(initial_run_response);
                            Arc::new(Mutex::new(new_run_task))
                        },
                        job_handle: None,
                    });

                    return Ok(SessionRunProgress {
                        cycle: session.cycle,
                        progress: 100,
                        updated_at: chrono::Utc::now().timestamp() as u64,
                        application_progress: 0,
                    });
                }

                // Execution of the run job task in separate thread
                let new_run_task = Arc::new(Mutex::new(RunTask::new(request_id, final_cycles)));
                // Closure that will run task in separate thread
                let task_closure = {
                    let task_final_cycles = Vec::from(final_cycles);
                    let run_task = Arc::clone(&new_run_task);
                    let job_session = Arc::clone(&session_mut);
                    let run_task_id = run_task.lock().await.id.clone();
                    move || {
                        // We must use separate tokio runtime here, as this is another
                        // system thread.
                        // todo! WARNING!! Check if this would work stable for many run requests
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .thread_name(&format!("Run job {}", &run_task_id))
                            .thread_stack_size(1024 * 1024)
                            .enable_time()
                            .build()
                            .unwrap();
                        // Run blocking async task in this dedicated OS thread
                        runtime.block_on(async {
                            let task_session_mut = job_session;
                            let first_cycle = *task_final_cycles.first().unwrap();
                            let last_cycle = *task_final_cycles.last().unwrap();
                            let total_cycles = last_cycle - first_cycle;
                            let task_id =  run_task.lock().await.id.clone();
                            let abort =  || {
                                log::warn!(
                                    "aborting task_id {}",
                                    &task_id,
                                );
                                panic!("aborting function task id {id} due to cancellation request", id=task_id);
                            };
                            // Actually perform work here
                            for cycle in task_final_cycles.clone() {
                                {
                                    let mut task_session = task_session_mut.lock().await;
                                    //Check if we need to abort
                                    match &task_session.current_job {
                                        None => {
                                            abort();
                                        }
                                        Some(job) => {
                                            if run_task_id != job.job_task.lock().await.id {
                                                abort();
                                            }
                                        }
                                    }
                                    // Execute run on remote machine
                                    match task_session.run_to_cycle(cycle).await {
                                        Ok(response) => {
                                            let mut current_task = run_task.lock().await;
                                            let is_halted = response.iflags_h;
                                            if response.iflags_y {
                                                //todo how to calculate application progress?
                                                //let _cmd = response.tohost[1];
                                                current_task.progress.application_progress = 0;
                                            }
                                            current_task.progress.progress = (((task_session.cycle-first_cycle) as f32/ total_cycles as f32) * 100.0) as u64;
                                            current_task.progress.cycle = task_session.cycle;
                                            current_task.progress.updated_at = chrono::Utc::now().timestamp() as u64;
                                            current_task.summaries.push(response);
                                            match task_session.get_root_hash().await {
                                                Ok(hash) => current_task.hashes.push(hash),
                                                Err(err) => {
                                                    panic!("unable to run further task id {id}, error: {err_msg}", id=task_id, err_msg = err.to_string());
                                                }
                                            };
                                            if is_halted {
                                                current_task.progress.halted = true;
                                                if &task_final_cycles.len() > &current_task.hashes.len() {
                                                    let last_hash = current_task.hashes.get(current_task.hashes.len()-1).unwrap().clone();
                                                    for _ in 1..&task_final_cycles.len() - current_task.hashes.len() {
                                                        current_task.hashes.push(last_hash.clone());
                                                    }
                                                }
                                                log::debug!(
                                                    "running task id {} progress: {}, session_id {}, curent cycle {} machine HALTED",
                                                    &current_task.id,
                                                    current_task.progress.progress,
                                                    &task_session.id,
                                                    &task_session.cycle
                                                );
                                                break;
                                            }
                                            log::debug!(
                                                "running task id {} increasing progress: {}, session_id {}, current cycle {}",
                                                &current_task.id,
                                                current_task.progress.progress,
                                                &task_session.id,
                                                &task_session.cycle
                                            );
                                        },
                                        Err(err) => {
                                            panic!("unable to run further task id {id}, error: {err_msg}", id=task_id, err_msg = err.to_string());
                                        }
                                    };
                                }
                            }
                        });
                    }
                };
                // Spawn running task in separate os thread
                let handle = std::thread::spawn(task_closure);
                session.current_job = Some(Job {
                    job_task: new_run_task,
                    job_handle: Some(handle),
                });
            } else {
                return Err(Box::new(CartesiSessionError::new(&format!(
                    "requested run cycle in history before snapshot, please recreate session with id {}" ,
                    &session.id
                ))));
            }
        } else {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "error executing run operation - no existing snapshot for session id {}",
                &session.id
            ))));
        }
        // Return current execution progress
        let (execution_progress, ..) = session.get_job_progress(request_id).await?;
        Ok(SessionRunProgress {
            cycle: execution_progress.cycle,
            progress: execution_progress.progress,
            updated_at: execution_progress.updated_at,
            application_progress: execution_progress.application_progress,
        })
    }

    pub async fn run_defective(
        session_mut: Arc<Mutex<Session>>,
        request_id: &str,
        final_cycles: &[u64],
    ) -> Result<SessionRunProgress, Box<dyn std::error::Error>> {

        let mut modified_cycles: Vec<u64> = Vec::new();
        for cycle in final_cycles {
            if cycle >= &MAX_CYCLE {
                modified_cycles.push(MAX_CYCLE);
            }
            else {
                modified_cycles.push(*cycle);
            }
        }
        
        log::info!(
            "Executing defective step.  Desired cycle: {:?}   Used cycle: {:?}",
            modified_cycles, final_cycles
        );

        let session_run_result = Session::run(session_mut.clone(), request_id, &modified_cycles);
        
        log::debug!(
            "Finished executing defective step.  Desired cycle: {:?}   Used cycle: {:?}",
            modified_cycles, final_cycles
        );
        
        match session_run_result.await{
            Ok(session_result) => {
                
                let session_result = SessionRunProgress {
                    progress: session_result.progress,
                    application_progress: session_result.application_progress,
                    updated_at: session_result.updated_at,
                    cycle: final_cycles[0],
                };

                log::debug!(
                    "Final response is: {:?}",
                    session_result
                );
                Ok(session_result)
            },
            Err(e) => {
                Err(e)
            }
        }
        
    }

    pub async fn step_defective(
        &mut self,
        cycle: u64,
        log_type: &grpc_cartesi_machine::AccessLogType,
        one_based: bool,
    ) -> Result<grpc_cartesi_machine::AccessLog, Box<dyn std::error::Error>> {
        let mut modified_cycle = cycle;

        if modified_cycle >= MAX_CYCLE {
            modified_cycle = MAX_CYCLE
        }

        log::debug!(
            "Executing defective step.  Desired cycle: {}   Used cycle: {}",
            modified_cycle, cycle
        );

        let session_step_result = self.step(modified_cycle, log_type, one_based);  
        
        log::debug!(
            "Finished executing defective step.  Desired cycle: {}   Used cycle: {}",
            modified_cycle, cycle
        );

        session_step_result.await
    }

    /// Perform step of machine instance on remote Cartesi machine emulator server
    pub async fn step(
        &mut self,
        cycle: u64,
        log_type: &grpc_cartesi_machine::AccessLogType,
        one_based: bool,
    ) -> Result<grpc_cartesi_machine::AccessLog, Box<dyn std::error::Error>> {
        if self.cycle != cycle {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "unexpected session cycle, current cycle is {}",
                self.cycle
            ))));
        }
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        let log = grpc_cartesi_machine.step(log_type, one_based).await?;
        let halted = grpc_cartesi_machine.read_csr(Csr::HtifIhalt).await?;
        self.cycle += 1;
        if halted > 0 {
            self.state = SessionState::Halted(self.cycle);
        } else {
            self.state = SessionState::Active;
        }
        Ok(log)
    }

    /// Perform store to directory of machine instance on remote Cartesi machine emulator server
    pub async fn store(&mut self, directory: &str) -> Result<(), Box<dyn std::error::Error>> {
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        match grpc_cartesi_machine.store(directory).await {
            Ok(_void) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Perform read memory on machine instance on remote Cartesi machine emulator server
    pub async fn read_mem(
        &mut self,
        cycle: u64,
        address: u64,
        length: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if self.state == SessionState::Halted(self.cycle) && cycle >= self.cycle {
            // In the case session machine is halted, reading bigger of equal cycle memory
            // always returns halted cycle value. Proceed with reading memory
        } else if self.cycle != cycle {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "unexpected session cycle, current cycle is {}",
                self.cycle
            ))));
        }
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        grpc_cartesi_machine.read_memory(address, length).await
    }

    /// Perform write memory on machine instance on remote Cartesi machine emulator server
    pub async fn write_mem(
        &mut self,
        cycle: u64,
        address: u64,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.cycle != cycle {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "unexpected session cycle, current cycle is {}",
                self.cycle
            ))));
        }
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        grpc_cartesi_machine.write_memory(address, data).await?;
        Ok(())
    }

    // Replace memory range on machine instance on remote Cartesi machine emulator server
    pub async fn replace_memory_range(
        &mut self,
        cycle: u64,
        range: &cartesi_grpc_interfaces::grpc_stubs::cartesi_machine::MemoryRangeConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.cycle != cycle {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "unexpected session cycle, current cycle is {}",
                self.cycle
            ))));
        }
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        grpc_cartesi_machine.replace_memory_range(range).await?;
        Ok(())
    }

    /// Get requested proof of machine instance on remote Cartesi machine emulator server
    pub async fn get_proof(
        &mut self,
        cycle: u64,
        address: u64,
        log2_size: u64,
    ) -> Result<MerkleTreeProof, Box<dyn std::error::Error>> {
        if self.state == SessionState::Halted(self.cycle) && cycle >= self.cycle {
            // In the case session machine is halted, reading bigger of equal cycle proof always
            // returns halted cycle proof value. Proceed with reading
        } else if self.cycle != cycle {
            return Err(Box::new(CartesiSessionError::new(&format!(
                "unexpected session cycle, current cycle is {}",
                self.cycle
            ))));
        }
        let grpc_cartesi_machine = self.get_cartesi_machine_client()?;
        grpc_cartesi_machine.get_proof(address, log2_size).await
    }

    /// Close session and inherently close Cartesi remote server instance using server manager api
    pub async fn close(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.state != SessionState::Closed {
            self.server_manager
                .lock()
                .await
                .close_server(&mut self.cartesi_session_client)?;
            self.state = SessionState::Closed;
        }
        Ok(())
    }
}

