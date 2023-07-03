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

extern crate cartesi_jsonrpc_interfaces;
extern crate getopts;
extern crate jsonrpc_machine_manager_server;
pub mod defective_session_registry;

use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine_manager::machine_manager_server;
use getopts::Options;
use jsonrpc_core::Params;
use std::env;

//use cartesi_jsonrpc_interfaces::machine_manager_server::MachineManagerServer;

use jsonrpc_machine_manager_server::MachineManagerService;

use async_mutex::Mutex;
use jsonrpc_machine_manager_server::server_manager::{LocalServerManager, ServerManager};
use jsonrpc_machine_manager_server::session_manager::{RamSessionManager, SessionManager};
use jsonrpc_machine_manager_server::{CARTESI_BIN_PATH, CARTESI_IMAGE_PATH};
use std::error::Error;
use std::sync::Arc;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [-h] [--address ADDRESS] [--port PORT]\n{} and {} environment variables must be set prior to running", program, &CARTESI_BIN_PATH, &CARTESI_IMAGE_PATH);
    print!("{}", opts.usage(&brief));
}

async fn run_machine_manager_service(
    session_manager: Arc<Mutex<dyn SessionManager>>,
    addr_checkin: std::net::SocketAddr,
) /*-> Result<(), Box<dyn std::error::Error + Send + Sync>> */{
    log::info!("addr_chekin addr_checkin {:?}", addr_checkin);
    let machine_manager_service = Arc::new(Mutex::new(MachineManagerService::new(session_manager.clone())));
    let machine_manager_service_ = MachineManagerService::new(session_manager);

    /*match Server::builder()
    .add_service(jsonrpc_machine_manager_server::machine_manager_server::MachineManagerServer::new(machine_manager_service_))
    .serve(addr_checkin).await
    {
         Ok(e)=> Ok(()),
        _ => Err(Box::new("")),
    };*/

    let machine_manager_server = jsonrpc_machine_manager_server::machine_manager_server::MachineManagerServer::new(machine_manager_service_);
    let mut io = jsonrpc_core::IoHandler::new();
    let rpc = RpcImpl;

    io.extend_with(rpc.to_delegate());
    log::info!("machine io {:?}", io);

    //io.extend_with(machine_manager_service_.to_delegate());
    let server = jsonrpc_http_server::ServerBuilder::new(io)
		.cors(jsonrpc_http_server::DomainsValidation::AllowOnly(vec![jsonrpc_http_server::AccessControlAllowOrigin::Null]))
		.start_http(&"0.0.0.0:50051".parse().unwrap())
		.expect("Unable to start RPC server");

	server.wait();

}

use jsonrpc_derive::rpc;

#[rpc(server)]
pub trait Rpc {
    #[rpc(name = "machine.machine.configg")]
        fn new_session(
            &self,
            machine_config: jsonrpc_cartesi_machine::MachineConfig,
            machine_runtime_config: jsonrpc_cartesi_machine::MachineRuntimeConfig,
        ) -> jsonrpc_core::BoxFuture<jsonrpc_core::Result<()>>;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    // Process command line arguments
    let mut opts = Options::new();
    opts.optopt("", "address", "Address to listen (default: localhost)", "");
    opts.optopt("p", "port", "Port to listen (default: 50051)", "");
    opts.optflag("", "verbose", "print more info about application execution");
    opts.optflag("h", "help", "show this help message and exit");
    let matches = opts.parse(&args[1..])?;
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(());
    }
    let host = matches.opt_get_default("address", "127.0.0.1".to_string())?;
    let port = matches.opt_get_default("port", 50051)?;
    //let defective = matches.opt_get_default("defective", false)?;

    // Set the global log level
    // Set log level of application
    let mut log_level = "info";
    if matches.opt_present("verbose") {
        log_level = "debug";
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    /*log::info!(
        "Starting check in service on address {}",
        format!("{}:{}", host, port_checkin)
    );*/
    let addr_machine_manager = format!("{}:{}", host, port);
    log::info!(
        "Starting machine manager service on address {}",
        format!("{}:{}", host, port)
    );
    // CARTESI_IMAGE_PATH and CARTESI_BIN_PATH must be set in environment
    if env::var(&CARTESI_IMAGE_PATH).is_err() {
        panic!(
            "Please specify environment {} variable that points to Cartesi emulator images folder",
            &CARTESI_IMAGE_PATH
        );
    }
    let cartesi_bin_path = match std::env::var(&CARTESI_BIN_PATH) {
        Ok(path) => path,
        Err(_) => panic!("Please specify environment {} variable that points to Cartesi machine server binaries folder", &CARTESI_BIN_PATH)
    };
    // Initialize server manager
    let server_manager: Arc<Mutex<dyn ServerManager>> =
        Arc::new(Mutex::new(LocalServerManager::new(
            &cartesi_bin_path,
            jsonrpc_machine_manager_server::server_manager::HOST,
        )));
    //Initialize session manager
    let session_manager: Arc<Mutex<dyn SessionManager>> = Arc::new(Mutex::new(
        RamSessionManager::new(&server_manager),
    ));
    let addr_machine_manager = format!("{}:{}", host, port).parse()?;

    //Run check in service and machine manager service
    //match tokio::try_join!(
        //run_checkin_service(addr_checkin, Arc::clone(&server_manager)),

        run_machine_manager_service(session_manager, addr_machine_manager).await;
        Ok(())
    /*) {
        Ok(_x) => Ok(()),
        Err(err) => Err(err),
    }*/
}
