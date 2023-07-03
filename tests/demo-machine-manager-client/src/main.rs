// Copyright 2023 Cartesi Pte. Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use
// this file except in compliance with the License. You may obtain a copy of the
// License at http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

use cartesi_jsonrpc_interfaces::index::{
    CLINTConfig, HTIFConfig, ProcessorConfig,
    MemoryRangeConfig, MachineConfig, MachineRuntimeConfig,
     RAMConfig, RollupConfig, ROMConfig, UarchConfig,
};
use jsonrpc_cartesi_machine::JsonRpcCartesiMachineClient;
use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine_manager::machine_manager_client::MachineManagerClient;
use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine_manager::*;
use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine::UarchProcessorConfig;
use cartesi_grpc_interfaces::grpc_stubs::cartesi_machine::UarchRamConfig;
pub const CARTESI_BIN_PATH: &str = "CARTESI_BIN_PATH";
pub const CARTESI_IMAGE_PATH: &str = "CARTESI_IMAGE_PATH";

pub fn generate_default_machine_config(files_dir: &str) -> jsonrpc_cartesi_machine::MachineConfig {
    jsonrpc_cartesi_machine::MachineConfig {
        processor:jsonrpc_cartesi_machine::ProcessorConfig {
            x: [0;32],
            f: [0;32],
            fcsr: 0,
            menvcfg: 0,
            senvcfg: 0,
            pc: 0x1000,
            mvendorid: 0x6361727465736920,
            marchid: 0xf,
            mimpid: 1,
            mcycle: 0,
            icycleinstret: 0,
            mstatus: 0,
            mtvec: 0,
            mscratch: 0,
            mepc: 0,
            mcause: 0,
            mtval: 0,
            misa: 0x800000000014112d,
            mie: 0,
            mip: 0,
            medeleg: 0,
            mideleg: 0,
            mcounteren: 0,
            stvec: 0,
            sscratch: 0,
            sepc: 0,
            scause: 0,
            stval: 0,
            satp: 0,
            scounteren: 0,
            ilrsc: u64::MAX,
            iflags: 0x0,
        },
        tlb: jsonrpc_cartesi_machine::TlbConfig {
            image_filename: "".to_string(),
        },
        uarch: jsonrpc_cartesi_machine::UarchConfig {
            processor: Some(cartesi_jsonrpc_interfaces::index::UarchProcessorConfig::default()),
            ram: Some(cartesi_jsonrpc_interfaces::index::UarchRAMConfig::default())
        },
        ram: jsonrpc_cartesi_machine::RamConfig {
            length: 64 << 20,
            image_filename: format!("{}/linux.bin", files_dir),
        },
        rom: jsonrpc_cartesi_machine::RomConfig {
            bootargs: String::from("console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rwmtdparts=flash.0:-(rootfs) -- for i in $(seq 0 5 1000); do yield progress $i; done"),
            image_filename: format!("{}/rom.bin", files_dir),
        },
        flash_drives: vec![jsonrpc_cartesi_machine::MemoryRangeConfig {
            start: 1 << 55,
            length: 71303168,
            image_filename: format!("{}/rootfs.ext2", files_dir),
            shared: false,
        }],
        clint: CLINTConfig {
            mtimecmp: Some(0),
        },
        htif: HTIFConfig {
            console_getchar: Some(false),
            yield_manual: Some(true),
            yield_automatic: Some(false),
            fromhost: Some(0),
            tohost: Some(0),
        },
        rollup: jsonrpc_cartesi_machine::RollupConfig {
            input_metadata: Some(jsonrpc_cartesi_machine::MemoryRangeConfig{
                start: 0x60400000,
                length: 4096,
                image_filename: "".to_string(),
                shared: false,
            }),
            notice_hashes: Some(jsonrpc_cartesi_machine::MemoryRangeConfig{
                start: 0x60800000,
                length: 2 << 20,
                image_filename: "".to_string(),
                shared: false,
            }),
            rx_buffer: Some(jsonrpc_cartesi_machine::MemoryRangeConfig{
                start: 0x60000000,
                length: 2 << 20,
                image_filename: "".to_string(),
                shared: false,
            }),
            voucher_hashes: Some(jsonrpc_cartesi_machine::MemoryRangeConfig{
                start: 0x60600000,
                length: 2 << 20,
                image_filename: "".to_string(),
                shared: false,
            }),
            tx_buffer: Some(jsonrpc_cartesi_machine::MemoryRangeConfig{
                start: 0x60200000,
                length: 2 << 20,
                image_filename: "".to_string(),
                shared: false,
            }),
        },
    }
}

pub fn generate_default_machine_rt_config() -> jsonrpc_cartesi_machine::MachineRuntimeConfig {
    jsonrpc_cartesi_machine::MachineRuntimeConfig {
        concurrency: jsonrpc_cartesi_machine::ConcurrencyConfig{
            update_merkle_tree: 0,
        },
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting demo machine client");
    //let session_id = "mysession";
    let image_file_root = std::env::var(&CARTESI_IMAGE_PATH).unwrap_or_else(|_| {
        panic!(
            "{} that points to folder with Cartesi images is not set",
            &CARTESI_IMAGE_PATH
        )
    });

    // Instantiate client
    let mut client = JsonRpcCartesiMachineClient::new("http://127.0.0.1:50051".to_string()).await?;
    // Create new session
    /*let machine = Some(MachineRequest {
        runtime: Some(generate_default_machine_rt_config()),
        machine_oneof: Some(machine_request::MachineOneof::Config(
            generate_default_machine_config(&image_file_root),
        )),
    });

    let request = tonic::Request::new(NewSessionRequest {
        machine,
        force: false,
    });*/
    println!("Session created\n");

    let response = client.create_machine(&generate_default_machine_config(&image_file_root), &generate_default_machine_rt_config()).await?;
    println!("Session created\n{:?}", response);

    loop {
        //Run to 20 cycle
        /*let request = tonic::Request::new(SessionRunRequest {
            final_cycles: vec![20],
            final_ucycles: vec![],
        });*/
        let response = client.run(20).await?;
        println!("response {:?}", response);
        /*if let Some(one_of) = response.into_inner().run_oneof {
            match one_of {
                session_run_response::RunOneof::Progress(progress) => {
                    println!(
                        "Running session, progress {}, cycle {}\n",
                        progress.progress, progress.cycle
                    );
                }
                session_run_response::RunOneof::Result(result) => {
                    println!(
                        "Job executed, resulting hash {:?}\n",
                        &result.hashes[0].data
                    );
                    break;
                }
            }
        }*/
    }

    // End session
    /*let request = tonic::Request::new(EndSessionRequest {
        silent: false,
    });*/
    let _response = client.shutdown().await?;
    println!("Session ended\n");
    Ok(())
}
