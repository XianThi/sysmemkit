use std::ffi::c_void;
pub type WORD = u16;
pub type DWORD = u32;
pub type QWORD = u64;
pub type BYTE = u8;
pub type LONG = i32;

pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;
pub const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;
pub const SYSTEM_EXTENDED_HANDLE_INFORMATION_CLASS: u32 = 0x40;
pub const DUPLICATE_CLOSE_SOURCE: u32 = 0x00000001;
pub const DUPLICATE_SAME_ACCESS: u32 = 0x00000002;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_FILE_HEADER {
    pub machine: WORD,
    pub number_of_sections: WORD,
    pub time_date_stamp: DWORD,
    pub pointer_to_symbol_table: DWORD,
    pub number_of_symbols: DWORD,
    pub size_of_optional_header: WORD,
    pub characteristics: WORD,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_DATA_DIRECTORY {
    pub virtual_address: DWORD,
    pub size: DWORD,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub magic: WORD,
    pub major_linker_version: BYTE,
    pub minor_linker_version: BYTE,
    pub size_of_code: DWORD,
    pub size_of_initialized_data: DWORD,
    pub size_of_uninitialized_data: DWORD,
    pub address_of_entry_point: DWORD,
    pub base_of_code: DWORD,
    pub image_base: QWORD,
    pub section_alignment: DWORD,
    pub file_alignment: DWORD,
    pub major_operating_system_version: WORD,
    pub minor_operating_system_version: WORD,
    pub major_image_version: WORD,
    pub minor_image_version: WORD,
    pub major_subsystem_version: WORD,
    pub minor_subsystem_version: WORD,
    pub win32_version_value: DWORD,
    pub size_of_image: DWORD,
    pub size_of_headers: DWORD,
    pub check_sum: DWORD,
    pub subsystem: WORD,
    pub dll_characteristics: WORD,
    pub size_of_stack_reserve: QWORD,
    pub size_of_stack_commit: QWORD,
    pub size_of_heap_reserve: QWORD,
    pub size_of_heap_commit: QWORD,
    pub loader_flags: DWORD,
    pub number_of_rva_and_sizes: DWORD,
    pub data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_NT_HEADERS64 {
    pub signature: DWORD,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub characteristics: DWORD,
    pub time_date_stamp: DWORD,
    pub major_version: WORD,
    pub minor_version: WORD,
    pub name: DWORD,
    pub base: DWORD,
    pub number_of_functions: DWORD,
    pub number_of_names: DWORD,
    pub address_of_functions: DWORD,
    pub address_of_names: DWORD,
    pub address_of_name_ordinals: DWORD,
}

#[repr(C)]
pub struct PEB {
    pub reserved1: [BYTE; 2],
    pub being_debugged: BYTE,
    pub reserved2: [BYTE; 1],
    pub reserved3: [*mut c_void; 2],
    pub ldr: *mut PEB_LDR_DATA,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub length: u32,
    pub initialized: u8,
    pub ss_handle: *mut c_void,
    pub in_load_order_module_list: LIST_ENTRY,
    pub in_memory_order_module_list: LIST_ENTRY,
    pub in_initialization_order_module_list: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub flink: *mut LIST_ENTRY,
    pub blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub in_load_order_links: LIST_ENTRY,
    pub in_memory_order_links: LIST_ENTRY,
    pub in_initialization_order_links: LIST_ENTRY,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: u32,
    pub full_dll_name: UNICODE_STRING,
    pub base_dll_name: UNICODE_STRING,
}


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct MEMORY_BASIC_INFORMATION {
    pub base_address: *mut c_void,    // 0x00
    pub allocation_base: *mut c_void, // 0x08
    pub allocation_protect: u32,      // 0x10
    pub _alignment: u16,              // 0x14
    pub region_size: usize,           // 0x18
    pub state: u32,                   // 0x20
    pub protect: u32,                 // 0x24
    pub type_field: u32,              // 0x28
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UNICODE_STRING {
    pub length: WORD,
    pub maximum_length: WORD,
    pub buffer: *mut u16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    pub process_id: u16,               // Offset 0x00
    pub creator_back_trace_index: u16, // Offset 0x02
    pub object_type_index: u8,         // Offset 0x04
    pub handle_attributes: u8,         // Offset 0x05
    pub handle_value: u16,             // Offset 0x06
    pub object: *mut c_void,           // Offset 0x08
    pub granted_access: u32,           // Offset 0x10
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct PROCESS_BASIC_INFORMATION {
    pub exit_status: i32,                        // 0x00
    pub peb_base_address: *mut c_void,           // 0x08
    pub affinity_mask: usize,                    // 0x10
    pub base_priority: i32,                      // 0x18
    pub unique_pid: usize,                       // 0x20
    pub inherited_from_unique_process_id: usize, // 0x28
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    pub object: *mut c_void,
    pub unique_process_id: usize,
    pub handle_value: usize,
    pub granted_access: u32,
    pub creator_back_trace_index: u16,
    pub object_type_index: u16,
    pub handle_attributes: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SYSTEM_HANDLE_INFORMATION_EX {
    pub number_of_handles: usize,
    pub reserved: usize,
    pub handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX; 1],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RUNTIME_FUNCTION {
    pub begin_address: u32,
    pub end_address: u32,
    pub unwind_data: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub number_of_handles: u32,
    pub handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 1],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: i64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: UNICODE_STRING,
    pub base_priority: i32,
    pub unique_process_id: *mut c_void,
    pub inherited_from_unique_process_id: *mut c_void,
}
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub length: u32,
    pub root_directory: *mut c_void,
    pub object_name: *mut c_void,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES_OPENFILE {
    pub length: u32,
    pub root_directory: *mut c_void,
    pub object_name: *mut UNICODE_STRING,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

#[repr(C)]
pub struct CLIENT_ID {
    pub unique_process: *mut c_void,
    pub unique_thread: *mut c_void,
}