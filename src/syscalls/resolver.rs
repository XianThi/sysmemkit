use crate::utils;
use std::arch::asm;
use std::ffi::c_void;

pub type WORD = u16;
pub type DWORD = u32;
pub type QWORD = u64;
pub type BYTE = u8;
pub type LONG = i32;

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
pub struct UNICODE_STRING {
    pub length: WORD,
    pub maximum_length: WORD,
    pub buffer: *mut u16,
}

pub unsafe fn get_dll_base(modulename: &str) -> (*mut c_void, usize) {
    let peb_ptr: *mut PEB;
    unsafe {
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb_ptr,
            options(nostack, readonly)
        );

        if peb_ptr.is_null() {
            return (std::ptr::null_mut(), 0);
        }

        let ldr = (*peb_ptr).ldr;
        if ldr.is_null() {
            return (std::ptr::null_mut(), 0);
        }

        let list_head = &(*ldr).in_load_order_module_list as *const LIST_ENTRY as *mut LIST_ENTRY;
        let mut current = (*list_head).flink;

        while current != list_head {
            let entry = current as *mut LDR_DATA_TABLE_ENTRY;

            if !entry.is_null() && !(*entry).dll_base.is_null() {
                let dll_name = &(*entry).base_dll_name;

                if !dll_name.buffer.is_null() && dll_name.length > 0 {
                    let name_len = (dll_name.length / 2) as usize;
                    let name_slice = std::slice::from_raw_parts(dll_name.buffer, name_len);
                    let name = String::from_utf16_lossy(name_slice);

                    if name.to_lowercase() == modulename {
                        let dll_base = (*entry).dll_base;
                        let size_of_image = (*entry).size_of_image;
                        return (dll_base, size_of_image as usize);
                    }
                }
            }

            current = (*current).flink;
        }

        return (std::ptr::null_mut(), 0);
    }
}

pub unsafe fn get_ntdll_base() -> (*mut c_void, usize) {
    return unsafe { get_dll_base("ntdll.dll") };
}

pub unsafe fn get_win32u_base() -> (*mut c_void, usize) {
    return unsafe { get_dll_base("win32u.dll") };
}

pub unsafe fn print_function_bytes(ntdll_base: *mut c_void, func_name: &str) {
    if ntdll_base.is_null() {
        return;
    }
    unsafe {
        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            return;
        }

        let nt_headers =
            (ntdll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        let export_dir_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        let export_dir =
            (ntdll_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names_ptr =
            (ntdll_base as usize + (*export_dir).address_of_names as usize) as *const u32;
        let functions_ptr =
            (ntdll_base as usize + (*export_dir).address_of_functions as usize) as *const u32;
        let ordinals_ptr =
            (ntdll_base as usize + (*export_dir).address_of_name_ordinals as usize) as *const u16;

        let num_names = (*export_dir).number_of_names;

        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (ntdll_base as usize + name_rva as usize) as *const i8;
            let current_name = std::ffi::CStr::from_ptr(name_ptr).to_str().unwrap_or("");

            if current_name == func_name {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *functions_ptr.add(ordinal as usize);
                let func_addr = (ntdll_base as usize + func_rva as usize) as *const u8;

                print!("İlk 32 byte: ");
                for j in 0..32 {
                    print!("{:02X} ", *func_addr.add(j));
                }

                break;
            }
        }
    }
}

pub unsafe fn get_ssn_by_hash(ntdll_base: *mut c_void, target_hash: u32) -> Option<u16> {
    if ntdll_base.is_null() {
        return None;
    }
    unsafe {
        let dos_header = ntdll_base as *const IMAGE_DOS_HEADER;
        if (*dos_header).e_magic != 0x5A4D {
            //MZ
            return None;
        }

        let nt_headers =
            (ntdll_base as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt_headers).signature != 0x00004550 {
            return None;
        }

        let export_dir_rva = (*nt_headers).optional_header.data_directory[0].virtual_address;
        if export_dir_rva == 0 {
            return None;
        }

        let export_dir =
            (ntdll_base as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let names_ptr =
            (ntdll_base as usize + (*export_dir).address_of_names as usize) as *const u32;
        let functions_ptr =
            (ntdll_base as usize + (*export_dir).address_of_functions as usize) as *const u32;
        let ordinals_ptr =
            (ntdll_base as usize + (*export_dir).address_of_name_ordinals as usize) as *const u16;

        let num_names = (*export_dir).number_of_names;

        for i in 0..num_names {
            let name_rva = *names_ptr.add(i as usize);
            let name_ptr = (ntdll_base as usize + name_rva as usize) as *const i8;

            let current_name = match std::ffi::CStr::from_ptr(name_ptr).to_str() {
                Ok(name) => name,
                Err(_) => continue,
            };

            let current_hash = utils::dbj2_hash(current_name);

            if current_hash == target_hash {
                let ordinal = *ordinals_ptr.add(i as usize);
                let func_rva = *functions_ptr.add(ordinal as usize);
                let func_addr = (ntdll_base as usize + func_rva as usize) as *const u8;

                for offset in 0..32 {
                    let byte = *func_addr.add(offset);

                    if byte == 0xB8 {
                        let ssn = *(func_addr.add(offset + 1) as *const u16);
                        if ssn != 0 && ssn != 0xFFFF {
                            return Some(ssn);
                        }
                    }

                    if offset + 4 < 32
                        && *func_addr.add(offset) == 0x4C
                        && *func_addr.add(offset + 1) == 0x8B
                        && *func_addr.add(offset + 2) == 0xD1
                        && *func_addr.add(offset + 3) == 0xB8
                    {
                        let ssn = *(func_addr.add(offset + 4) as *const u16);
                        if ssn != 0 && ssn != 0xFFFF {
                            return Some(ssn);
                        }
                    }
                }

                return Some(0);
            }
        }

        None
    }
}

pub unsafe fn get_syscall_number(ntdll_base: *mut c_void, func_hash: u32) -> Option<u16> {
    unsafe {
        if ntdll_base.is_null() {
            return None;
        }
        get_ssn_by_hash(ntdll_base, func_hash)
    }
}

pub unsafe fn get_syscall_number_by_name(ntdll_base: *mut c_void, func_name: &str) -> Option<u16> {
    unsafe {
        let hash = utils::dbj2_hash(func_name);
        get_syscall_number(ntdll_base, hash)
    }
}
