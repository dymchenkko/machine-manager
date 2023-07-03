
#[macro_use]
use jsonrpc_client_core;

extern crate serde;
extern crate serde_json;
extern crate derive_builder;

use serde::{Serialize, Deserialize};
use derive_builder::Builder;
pub type UnsignedInteger = u64;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct CLINTConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtimecmp: Option<UnsignedInteger>,
}
pub type StringDoaGddGA = String;
pub type BooleanVyG3AETh = bool;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct MemoryRangeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_filename: Option<StringDoaGddGA>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared: Option<BooleanVyG3AETh>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<UnsignedInteger>,
}
pub type FlashDriveConfigs = Vec<MemoryRangeConfig>;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct HTIFConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_getchar: Option<BooleanVyG3AETh>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fromhost: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tohost: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yield_automatic: Option<BooleanVyG3AETh>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yield_manual: Option<BooleanVyG3AETh>,
}
pub type FRegConfig = Vec<UnsignedInteger>;
pub type XRegConfig = Vec<UnsignedInteger>;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct ProcessorConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub f: Option<FRegConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcsr: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icycleinstret: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iflags: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ilrsc: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marchid: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcause: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcounteren: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcycle: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub medeleg: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub menvcfg: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mepc: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mideleg: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mie: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mimpid: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mip: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub misa: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mscratch: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mstatus: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtval: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtvec: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mvendorid: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pc: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub satp: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scause: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scounteren: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub senvcfg: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sepc: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sscratch: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stval: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stvec: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<XRegConfig>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct RAMConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_filename: Option<StringDoaGddGA>,
    pub length: UnsignedInteger,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct RollupConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_metadata: Option<MemoryRangeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice_hashes: Option<MemoryRangeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_buffer: Option<MemoryRangeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_buffer: Option<MemoryRangeConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub voucher_hashes: Option<MemoryRangeConfig>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct ROMConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootargs: Option<StringDoaGddGA>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_filename: Option<StringDoaGddGA>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct TLBConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_filename: Option<StringDoaGddGA>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct UarchProcessorConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cycle: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pc: Option<UnsignedInteger>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<XRegConfig>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct UarchRAMConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_filename: Option<StringDoaGddGA>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<UnsignedInteger>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct UarchConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor: Option<UarchProcessorConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ram: Option<UarchRAMConfig>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct ConcurrencyConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_merkle_tree: Option<UnsignedInteger>,
}
pub type Base64Hash = String;
pub type Base64HashArray = Vec<Base64Hash>;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct Proof {
    #[serde(rename = "log2_root_size")]
    pub log_2_root_size: UnsignedInteger,
    #[serde(rename = "log2_target_size")]
    pub log_2_target_size: UnsignedInteger,
    pub root_hash: Base64Hash,
    pub sibling_hashes: Base64HashArray,
    pub target_address: UnsignedInteger,
    pub target_hash: Base64Hash,
}
pub type Base64String = String;
pub type AccessType = serde_json::Value;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct Access {
    pub address: UnsignedInteger,
    #[serde(rename = "log2_size")]
    pub log_2_size: UnsignedInteger,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    pub read: Base64String,
    #[serde(rename = "type")]
    pub r#type: AccessType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub written: Option<Base64String>,
}
pub type AccessArray = Vec<Access>;
pub type BracketType = serde_json::Value;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct Bracket {
    pub text: StringDoaGddGA,
    #[serde(rename = "type")]
    pub r#type: BracketType,
    pub r#where: UnsignedInteger,
}
pub type BracketArray = Vec<Bracket>;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct AccessLogType {
    pub has_annotations: BooleanVyG3AETh,
    pub has_proofs: BooleanVyG3AETh,
}
pub type NoteArray = Vec<StringDoaGddGA>;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct MachineConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clint: Option<CLINTConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flash_drive: Option<FlashDriveConfigs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub htif: Option<HTIFConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor: Option<ProcessorConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ram: Option<RAMConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollup: Option<RollupConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rom: Option<ROMConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tlb: Option<TLBConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uarch: Option<UarchConfig>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct MachineRuntimeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<ConcurrencyConfig>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Builder, Default)]
#[builder(setter(strip_option), default)]
#[serde(default)]
pub struct AccessLog {
    pub accesses: AccessArray,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brackets: Option<BracketArray>,
    pub log_type: AccessLogType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<NoteArray>,
}
pub type CSR = serde_json::Value;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct SemanticVersion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<StringDoaGddGA>,
    pub major: UnsignedInteger,
    pub minor: UnsignedInteger,
    pub patch: UnsignedInteger,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_release: Option<StringDoaGddGA>,
}
pub type InterpreterBreakReason = serde_json::Value;
pub type UarchInterpreterBreakReason = serde_json::Value;
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum AnyOfMachineConfigMachineRuntimeConfigStringDoaGddGAMachineRuntimeConfigStringDoaGddGAUnsignedIntegerUnsignedIntegerAccessLogTypeBooleanVyG3AEThAccessLogMachineRuntimeConfigBooleanVyG3AEThAccessLogAccessLogAccessLogMachineRuntimeConfigBooleanVyG3AEThUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerBase64StringUnsignedIntegerUnsignedIntegerUnsignedIntegerBase64StringMemoryRangeConfigCSRCSRUnsignedIntegerCSRUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerStringDoaGddGABooleanVyG3AEThSemanticVersionBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThInterpreterBreakReasonUarchInterpreterBreakReasonAccessLogBooleanVyG3AEThBooleanVyG3AEThProofBase64HashProofUnsignedIntegerBase64StringBooleanVyG3AEThBase64StringBooleanVyG3AEThBooleanVyG3AEThUnsignedIntegerBooleanVyG3AEThUnsignedIntegerUnsignedIntegerUnsignedIntegerUnsignedIntegerBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThUnsignedIntegerUnsignedIntegerUnsignedIntegerBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThUnsignedIntegerBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AEThMachineConfigMachineConfigBooleanVyG3AEThBooleanVyG3AEThBooleanVyG3AETh {
    MachineConfig(MachineConfig),
    MachineRuntimeConfig(MachineRuntimeConfig),
    StringDoaGddGA(StringDoaGddGA),
    UnsignedInteger(UnsignedInteger),
    AccessLogType(AccessLogType),
    BooleanVyG3AETh(BooleanVyG3AETh),
    AccessLog(AccessLog),
    Base64String(Base64String),
    MemoryRangeConfig(MemoryRangeConfig),
    CSR(CSR),
    SemanticVersion(SemanticVersion),
    InterpreterBreakReason(InterpreterBreakReason),
    UarchInterpreterBreakReason(UarchInterpreterBreakReason),
    Proof(Proof),
    Base64Hash(Base64Hash),
}
#[derive(Clone)]
pub struct RemoteCartesiMachine<T> {
    transport:T,
}
impl<T: jsonrpc_client_core::Transport> RemoteCartesiMachine<T> {
    pub fn new(transport: T) -> Self {
        RemoteCartesiMachine { transport }
    }

    pub fn CheckConnection(&mut self) -> jsonrpc_client_core::RpcRequest<String, T::Future> {
        let method = "";
        log::info!("Check connection");

        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn Fork(&mut self) -> jsonrpc_client_core::RpcRequest<StringDoaGddGA, T::Future> {
        let method = "fork";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn Shutdown(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "shutdown";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn GetVersion(&mut self) -> jsonrpc_client_core::RpcRequest<SemanticVersion, T::Future> {
        let method = "get_version";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineMachineConfig(&mut self, config: MachineConfig, runtime: MachineRuntimeConfig) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.machine.config";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(config), serde_json::json!(runtime)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineMachineDirectory(&mut self, directory: StringDoaGddGA , runtime: MachineRuntimeConfig) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.machine.directory";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(directory), serde_json::json!(runtime)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineDestroy(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.destroy";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineStore(&mut self, directory: StringDoaGddGA) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.store";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(directory)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineRun(&mut self, mcycle_end: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<InterpreterBreakReason, T::Future> {
        let method = "machine.run";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(mcycle_end)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineRunUarch(&mut self, uarch_cycle_end: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UarchInterpreterBreakReason, T::Future> {
        let method = "machine.run_uarch";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(uarch_cycle_end)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineStepUarch(&mut self, log_type: AccessLogType, one_based: BooleanVyG3AETh) -> jsonrpc_client_core::RpcRequest<AccessLog, T::Future> {
        let method = "machine.step_uarch";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(log_type), serde_json::json!(one_based)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineVerifyAccessLog(&mut self, log: AccessLog, runtime: MachineRuntimeConfig, one_based: BooleanVyG3AETh) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.verify_access_log";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(log), serde_json::json!(runtime), serde_json::json!(one_based)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineVerifyStateTransition(&mut self, root_hash_before: String, log: AccessLog, root_hash_after: String, runtime: MachineRuntimeConfig, one_based: BooleanVyG3AETh) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.verify_state_transition";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(root_hash_before), serde_json::json!(log), serde_json::json!(root_hash_after), serde_json::json!(runtime), serde_json::json!(one_based)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetProof(&mut self, address: UnsignedInteger, log2_size: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<Proof, T::Future> {
        let method = "machine.get_proof";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(address), serde_json::json!(log2_size)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetRootHash(&mut self) -> jsonrpc_client_core::RpcRequest<Base64Hash, T::Future> {
        let method = "machine.get_root_hash";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadWord(&mut self, address: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.read_word";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(address)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadMemory(&mut self, address: UnsignedInteger, length: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<Base64String, T::Future> {
        let method = "machine.read_memory";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(address), serde_json::json!(length)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineWriteMemory(&mut self, address: UnsignedInteger, data: Base64String) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.write_memory";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(address), serde_json::json!(data)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadVirtualMemory(&mut self, address: UnsignedInteger, length: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<Base64String, T::Future> {
        let method = "machine.read_virtual_memory";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(address), serde_json::json!(length)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineWriteVirtualMemory(&mut self, address: UnsignedInteger, data: Base64String) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.write_virtual_memory";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(address), serde_json::json!(data)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReplaceMemoryRange(&mut self, range: MemoryRangeConfig) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.replace_memory_range";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(range)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadCsr(&mut self, csr: String) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.read_csr";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(csr)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineWriteCsr(&mut self, csr: String, value: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.write_csr";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(csr), serde_json::json!(value)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetCsrAddress(&mut self, csr: String) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.get_csr_address";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(csr)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadX(&mut self, index: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.read_x";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadF(&mut self, index: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.read_f";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadUarchX(&mut self, index: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.read_uarch_x";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineWriteX(&mut self, index: UnsignedInteger, value: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.write_x";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index), serde_json::json!(value)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineWriteF(&mut self, index: UnsignedInteger, value: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.write_f";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index), serde_json::json!(value)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineWriteUarchX(&mut self, index: UnsignedInteger, value: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.write_uarch_x";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index), serde_json::json!(value)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetXAddress(&mut self, index: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.get_x_address";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetFAddress(&mut self, index: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.get_f_address";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetUarchXAddress(&mut self, index: UnsignedInteger) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.get_uarch_x_address";
        let params: Vec<serde_json::Value> = vec![serde_json::json!(index)];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineSetIflagsY(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.set_iflags_Y";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineResetIflagsY(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.reset_iflags_Y";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadIflagsY(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.read_iflags_Y";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineSetIflagsX(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.set_iflags_X";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineResetIflagsX(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.reset_iflags_X";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadIflagsX(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.read_iflags_X";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineSetIflagsH(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.set_iflags_H";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadIflagsH(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.read_iflags_H";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadIflagsPRV(&mut self) -> jsonrpc_client_core::RpcRequest<UnsignedInteger, T::Future> {
        let method = "machine.read_iflags_PRV";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineSetUarchHaltFlag(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.set_uarch_halt_flag";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineReadUarchHaltFlag(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.read_uarch_halt_flag";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineResetUarchState(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.reset_uarch_state";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetInitialConfig(&mut self) -> jsonrpc_client_core::RpcRequest<MachineConfig, T::Future> {
        let method = "machine.get_initial_config";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineGetDefaultConfig(&mut self) -> jsonrpc_client_core::RpcRequest<MachineConfig, T::Future> {
        let method = "machine.get_default_config";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineVerifyMerkleTree(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.verify_merkle_tree";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineVerifyDirtyPageMaps(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.verify_dirty_page_maps";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }

    pub fn MachineDumpPmas(&mut self) -> jsonrpc_client_core::RpcRequest<BooleanVyG3AETh, T::Future> {
        let method = "machine.dump_pmas";
        let params: Vec<serde_json::Value> = vec![];
        jsonrpc_client_core::call_method(&mut self.transport, method.to_string(), params)
    }
}
