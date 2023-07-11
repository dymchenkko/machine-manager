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

//! Server manager is responsible for instantiation and closing of remote-cartesi-machine
//! instances. It also keeps list of active host and port remote-cartesi-machine instances,
//! which use check in mechanism to communicate their host and port.

use async_mutex::Mutex;
use async_trait::async_trait;
use jsonrpc_cartesi_machine::JsonRpcCartesiMachineClient;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::collections::HashMap;
use std::sync::Arc;

pub const HOST: &str = "127.0.0.1";

/// Error type returned from server manager functions
#[derive(Debug, Default)]
struct CartesiServerManagerError {
    message: String,
}

impl CartesiServerManagerError {
    fn new(message: &str) -> Self {
        CartesiServerManagerError {
            message: String::from(message),
        }
    }
}

impl std::fmt::Display for CartesiServerManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Jsonrpc cartesi server manager error: {}", &self.message)
    }
}

impl std::error::Error for CartesiServerManagerError {}

/// Structure that represents Cartesi machine client targeting
/// remote Cartesi machine server used in session
#[derive(Clone)]
pub struct CartesiSessionMachineClient {
    pub server_id: String,
    pub cartesi_machine_client: Option<JsonRpcCartesiMachineClient>,
    pub server_host: String,
    pub port: u32,
    pid: u32,
}

impl Default for CartesiSessionMachineClient {
    fn default() -> Self {
        CartesiSessionMachineClient {
            cartesi_machine_client: None,
            server_host: Default::default(),
            port: 0,
            server_id: Default::default(),
            pid: 0,
        }
    }
}

impl CartesiSessionMachineClient {
    /// Create new Cartesi session machine client with provided params
    fn new(server_id: &str, server_host: &str, port: u32, pid: u32) -> CartesiSessionMachineClient {
        CartesiSessionMachineClient {
            server_id: server_id.to_string(),
            server_host: server_host.to_string(),
            cartesi_machine_client: None,
            pid,
            port,
        }
    }

    /// Return process id (for local server process) of the OS process where Cartesi server instance is running
    pub fn get_server_process_pid(&self) -> u32 {
        self.pid
    }

    /// Returns uri of the Cartesi server
    pub fn get_server_address(&self) -> String {
        format!("http://{}:{}", self.server_host, self.port)
    }

    /// Returns server id of the server
    pub fn get_server_id(&self) -> String {
        self.server_id.clone()
    }

    /// Connect to server
    pub(super) async fn connect_to_server(
        &mut self,
        cartesi_server_address: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        log::info!("connect_to_server address {}", cartesi_server_address);
        self.cartesi_machine_client =
            match JsonRpcCartesiMachineClient::new(format!("http://{}", cartesi_server_address))
                .await
            {
                Ok(machine) => {
                    log::info!(
                        "connected to remote Cartesi machine {}",
                        cartesi_server_address
                    );
                    Some(machine)
                }
                Err(err) => {
                    log::info!(
                        "unable to connect to Cartesi machine server: {}",
                        err.to_string()
                    );
                    self.cartesi_machine_client = None;

                    return Err(Box::new(CartesiServerManagerError::new(
                        format!(
                            "unable to connect to Cartesi machine server: {}",
                            err.to_string()
                        )
                        .as_str(),
                    )));
                }
            };
        Ok(())
    }
}

/// Instantiate local Cartesi machine server in subprocess
fn instantiate_local_server_instance(
    cartesi_bin_path: &str,
    host: &str,
    port: u32,
) -> Result<u32, Box<dyn std::error::Error>> {
    let address = format!("{}:{}", host, port);
    log::info!(
        "instantiating remote Cartesi machine on address {}",
        address,
    );
    let cartesi_server_bin = format!("{}/jsonrpc-remote-cartesi-machine", cartesi_bin_path);
    let output = std::process::Command::new(cartesi_server_bin)
        .arg(&format!("--server-address={}", &address))
        .spawn()
        .expect("unable to launch remoete Cartesi machine");
    log::info!("remote cartesi machine started pid='{}'", output.id());
    Ok(output.id())
}

/// Kill process with provided pid
fn try_stop_process(pid: u32) -> std::process::ExitStatus {
    let error_message = format!("error destroying process with pid {}", pid);
    let mut child = std::process::Command::new("kill")
        .arg(&pid.to_string())
        .spawn()
        .expect(&error_message);
    child.wait().expect(&error_message)
}

/// Interface for server manager
/// Warning: every concrete implementation of the server manager must
/// be thread safe (Sync, Send)
#[async_trait]
pub trait ServerManager: Send + Sync {
    /// Create instance of new Cartesi machine server
    async fn instantiate_server(
        &mut self,
        session_id: &str,
    ) -> Result<CartesiSessionMachineClient, Box<dyn std::error::Error + '_>>;
    /// Close instance of Cartesi machine server
    fn close_server(
        &self,
        session_client: &mut CartesiSessionMachineClient,
    ) -> Result<(), Box<dyn std::error::Error>>;
    fn add_address(&mut self, session_id: &str, address: &str);

    fn get_address(&mut self, session_id: &str) -> String;
}

/// Implementation of the server manager that instantiates Cartesi machine servers
/// on local machine as subprocesses
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct LocalServerManager {
    pub cartesi_bin_path: Arc<String>,
    pub host: Arc<String>,
    port_counter: Arc<Mutex<u32>>,
    connected_servers: std::collections::HashMap<String, String>,
}

#[allow(dead_code)]
impl LocalServerManager {
    pub fn new(cartesi_bin_path: &str, host: &str) -> LocalServerManager {
        LocalServerManager {
            cartesi_bin_path: Arc::new(cartesi_bin_path.to_string()),
            host: Arc::new(host.to_string()),
            port_counter: Arc::new(Mutex::new(5000)),
            connected_servers: HashMap::new(),
        }
    }

    fn generate_server_id() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(12)
            .map(char::from)
            .collect()
    }
}

#[async_trait]
impl ServerManager for LocalServerManager {
    /// Spawn new Cartesi machine server subprocess and return
    /// matching Cartesi machine client for that server
    async fn instantiate_server(
        &mut self,
        session_id: &str,
    ) -> Result<CartesiSessionMachineClient, Box<dyn std::error::Error + '_>> {
        let port = {
            // Let Cartesi machine server to select port
            0
        };
        let cartesi_bin_path = Arc::clone(&self.cartesi_bin_path);
        let host = Arc::clone(&self.host);
        let mut new_cartesi_session_machine_client = CartesiSessionMachineClient::new(
            &LocalServerManager::generate_server_id(),
            &self.host,
            port,
            0,
        );
        let address = format!("{}:{}", host, port);
        let actual_port ={
            let listener = std::net::TcpListener::bind(address)?;
            let actual_port = listener.local_addr()?.port() as u32;
            actual_port
        };
        let pid = instantiate_local_server_instance(&cartesi_bin_path, &host, actual_port)?;
        self.add_address(session_id, &(host.to_string() + ":" + &actual_port.to_string()));
        new_cartesi_session_machine_client.pid = pid;
        Ok(new_cartesi_session_machine_client)
    }

    /// Close Cartesi machine serer subprocess
    fn close_server(
        &self,
        session_client: &mut CartesiSessionMachineClient,
    ) -> Result<(), Box<dyn std::error::Error>> {
        log::debug!(
            "closing server server_id: {} pid: {} ",
            session_client.server_id,
            session_client.pid
        );
        let status = try_stop_process(session_client.pid);
        if status.success() {
            session_client.cartesi_machine_client = None;
            Ok(())
        } else {
            let error_message = format!(
                "Server process with pid {} not terminated, error code {}",
                session_client.pid,
                status.code().unwrap_or(0)
            );
            log::error!("{}", &error_message);
            Err(Box::new(CartesiServerManagerError::new(&error_message)))
        }
    }
    fn add_address(&mut self, session_id: &str, address: &str) {
        self.connected_servers
            .insert(session_id.to_string(), address.to_string());
    }
    fn get_address(&mut self, session_id: &str) -> String {
        log::info!("connected_servers {:?}", self.connected_servers);
        match self.connected_servers.get(session_id) {
            Some(address) => address.clone(),
            None => Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::CARTESI_BIN_PATH;
    use rstest::*;

    #[rstest]
    #[tokio::test]
    async fn create_server_manager() {
        let host = "127.0.0.1".to_string();
        let cartesi_bin_path = std::env::var(&CARTESI_BIN_PATH).unwrap();

        let new_server_manager = LocalServerManager::new(&cartesi_bin_path, &host);
        assert_eq!(*new_server_manager.host, host);
        assert_eq!(*new_server_manager.cartesi_bin_path, cartesi_bin_path);
        assert_eq!(*new_server_manager.port_counter.lock().await, 5000);
    }
}
