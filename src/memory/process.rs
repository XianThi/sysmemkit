use std::ffi::c_void;
use std::ptr::{null, null_mut};

pub type WORD = u16;
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
pub struct CLIENT_ID {
    pub unique_process: *mut c_void,
    pub unique_thread: *mut c_void,
}

pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const SYSTEM_PROCESS_INFORMATION_CLASS: u32 = 5;

const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

use crate::syscalls::invoker::do_syscall;
use crate::syscalls::resolver::{get_ntdll_base, get_ssn_by_hash, print_function_bytes};
use crate::utils::dbj2_hash;

pub unsafe fn get_pid_by_hash(target_name_hash: u32) -> Option<u32> {
    unsafe {
        let ntdll = get_ntdll_base();
        let nt_query_hash = dbj2_hash("NtQuerySystemInformation");

        let ssn_query = get_ssn_by_hash(ntdll, nt_query_hash)?;
        print!(
            "{} nt_query_hash için syscall numarası bulundu! SSN: {}.\r\n",
            nt_query_hash, ssn_query
        );
        let mut buffer_size = 0x40000;
        let mut buffer =
            std::alloc::alloc(std::alloc::Layout::from_size_align(buffer_size, 16).unwrap());
        let mut ret_len: usize = 0;
        let mut args = [
            SYSTEM_PROCESS_INFORMATION_CLASS as usize,
            buffer as usize,
            buffer_size,
            &mut ret_len as *mut _ as usize,
            0,
        ];

        let mut status = do_syscall(ssn_query, args.as_mut_ptr());
        if status == 0xC0000004 {
            std::alloc::dealloc(
                buffer,
                std::alloc::Layout::from_size_align(buffer_size, 16).unwrap(),
            );
            buffer_size = ret_len + 0x1000;
            buffer =
                std::alloc::alloc(std::alloc::Layout::from_size_align(buffer_size, 16).unwrap());

            args[1] = buffer as usize;
            args[2] = buffer_size;
            status = do_syscall(ssn_query, args.as_mut_ptr());
        }
        if status != 0 {
            std::alloc::dealloc(
                buffer,
                std::alloc::Layout::from_size_align(buffer_size, 16).unwrap(),
            );
            return None;
        }

        let mut current_ptr = buffer;
        loop {
            let proc_info = current_ptr as *mut SYSTEM_PROCESS_INFORMATION;

            if !(*proc_info).image_name.buffer.is_null() {
                let name_len = (*proc_info).image_name.length as usize / 2;
                let name_slice =
                    std::slice::from_raw_parts((*proc_info).image_name.buffer, name_len);

                let name_string = String::from_utf16_lossy(name_slice);

                if dbj2_hash(&name_string.to_lowercase()) == target_name_hash {
                    let pid = (*proc_info).unique_process_id as u32;
                    std::alloc::dealloc(
                        buffer,
                        std::alloc::Layout::from_size_align(0x10000, 8).unwrap(),
                    );
                    return Some(pid);
                }
            }

            let next_offset = (*proc_info).next_entry_offset;
            if next_offset == 0 {
                break;
            }
            current_ptr = current_ptr.add(next_offset as usize);
        }

        std::alloc::dealloc(
            buffer,
            std::alloc::Layout::from_size_align(0x10000, 8).unwrap(),
        );
        None
    }
}

pub unsafe fn manual_open_process(pid: u32) -> Option<*mut c_void> {
    unsafe {
        let ntdll = get_ntdll_base();
        if ntdll.is_null() {
            return None;
        }

        let nt_open_hash = dbj2_hash("NtOpenProcess");
        let ssn_open = match get_ssn_by_hash(ntdll, nt_open_hash) {
            Some(ssn) => ssn,
            None => {
                return None;
            }
        };

        let mut handle: *mut c_void = std::ptr::null_mut();

        let mut obj_attr = OBJECT_ATTRIBUTES {
            length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            root_directory: std::ptr::null_mut(),
            object_name: std::ptr::null_mut(),
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        };

        let mut client_id = CLIENT_ID {
            unique_process: pid as *mut c_void,
            unique_thread: std::ptr::null_mut(),
        };

        let access_mask =
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;

        let mut args = [
            &mut handle as *mut _ as usize,
            access_mask as usize,
            &mut obj_attr as *mut _ as usize,
            &mut client_id as *mut _ as usize,
        ];

        let status = do_syscall(ssn_open, args.as_mut_ptr());

        if status == 0 && !handle.is_null() {
            let ssn_query = get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess")).unwrap();
            let mut pbi = PROCESS_BASIC_INFORMATION::default();
            let mut ret_len = 0u32;

            let mut test_args = [
                handle as usize,
                0,
                &mut pbi as *mut _ as usize,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as usize,
                &mut ret_len as *mut _ as usize,
            ];

            let test_status = do_syscall(ssn_query, test_args.as_mut_ptr());
            if test_status == 0 {
                return Some(handle);
            } else {
                let nt_close_hash = dbj2_hash("NtClose");
                let ssn_close = get_ssn_by_hash(ntdll, nt_close_hash).unwrap();
                let mut close_args = [handle as usize];
                do_syscall(ssn_close, close_args.as_mut_ptr());
                return None;
            }
        }

        None
    }
}

pub unsafe fn hijack_handle(target_pid: u32) -> Option<*mut c_void> {
    unsafe {
        match manual_open_process(target_pid) {
            Some(h) => return Some(h),
            None => {
                return None;
            }
        };
    }
}

unsafe fn read_remote<T>(handle: *mut c_void, ssn: u16, addr: usize, out: *mut T) -> bool {
    let mut bytes_read = 0usize;
    let mut args = [
        handle as usize,
        addr,
        out as usize,
        std::mem::size_of::<T>(),
        &mut bytes_read as *mut usize as usize,
    ];
    let status = unsafe { do_syscall(ssn, args.as_mut_ptr()) };
    if status != 0 {}
    status == 0
}

unsafe fn read_remote_buffer(
    handle: *mut c_void,
    ssn: u16,
    addr: usize,
    out: usize,
    size: usize,
) -> bool {
    let mut bytes_read = 0usize;
    let mut args = [
        handle as usize,
        addr,
        out,
        size,
        &mut bytes_read as *mut usize as usize,
    ];
    let status = unsafe { do_syscall(ssn, args.as_mut_ptr()) };
    if status != 0 {}
    status == 0
}

pub unsafe fn get_module_base(process_handle: *mut c_void, module_name_hash: u32) -> Option<usize> {
    unsafe {
        if process_handle.is_null() || process_handle == -1isize as *mut c_void {
            return None;
        }

        let ntdll = get_ntdll_base();
        if ntdll.is_null() {
            return None;
        }

        let ssn_query = get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess"))?;
        let ssn_read = get_ssn_by_hash(ntdll, dbj2_hash("NtReadVirtualMemory"))?;

        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        let mut ret_len = 0u32;

        let mut args_query = [
            process_handle as usize,
            0,
            &mut pbi as *mut _ as usize,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as usize,
            &mut ret_len as *mut _ as usize,
        ];

        let status = do_syscall(ssn_query, args_query.as_mut_ptr());
        if status != 0 {
            return get_module_base_alternative(process_handle, module_name_hash, ssn_read);
        }

        let peb_addr = pbi.peb_base_address as usize;
        if peb_addr == 0 {
            return None;
        }

        let ldr_offsets = [0x18, 0x10, 0x20, 0x30];
        let mut ldr_ptr: usize = 0;
        let mut found = false;

        for &offset in &ldr_offsets {
            if read_remote(process_handle, ssn_read, peb_addr + offset, &mut ldr_ptr) {
                if ldr_ptr != 0 {
                    found = true;
                    break;
                }
            } else {
            }
        }

        if !found {
            let mut peb_data = [0u8; 64];
            if read_remote_buffer(
                process_handle,
                ssn_read,
                peb_addr,
                peb_data.as_mut_ptr() as usize,
                64,
            ) {}
            return None;
        }

        let list_offsets = [0x10, 0x14, 0x18, 0x20];
        let mut current_link: usize = 0;
        found = false;

        for &offset in &list_offsets {
            if read_remote(
                process_handle,
                ssn_read,
                ldr_ptr + offset,
                &mut current_link,
            ) {
                if current_link != 0 {
                    found = true;
                    break;
                }
            }
        }

        if !found {
            return None;
        }

        let start_link = current_link;

        let mut iteration = 0;

        loop {
            iteration += 1;
            if iteration > 500 {
                break;
            }

            if current_link == 0 {
                break;
            }

            let dll_base_offsets = [0x30, 0x28, 0x38, 0x40];
            let mut dll_base: usize = 0;
            let mut base_found = false;

            for &offset in &dll_base_offsets {
                if read_remote(
                    process_handle,
                    ssn_read,
                    current_link + offset,
                    &mut dll_base,
                ) && dll_base != 0
                {
                    base_found = true;
                    break;
                }
            }

            if !base_found {
                break;
            }

            let name_offsets = [0x58, 0x48, 0x50, 0x60];
            let mut name_found = false;

            for &offset in &name_offsets {
                let mut name_unicode = UNICODE_STRING {
                    length: 0,
                    maximum_length: 0,
                    buffer: std::ptr::null_mut(),
                };

                if read_remote(
                    process_handle,
                    ssn_read,
                    current_link + offset,
                    &mut name_unicode,
                ) {
                    if !name_unicode.buffer.is_null() && name_unicode.length > 0 {
                        let name_len = (name_unicode.length / 2) as usize;
                        let mut name_buf = vec![0u16; name_len];

                        if read_remote_buffer(
                            process_handle,
                            ssn_read,
                            name_unicode.buffer as usize,
                            name_buf.as_mut_ptr() as usize,
                            name_len * 2,
                        ) {
                            let name = String::from_utf16_lossy(&name_buf).to_lowercase();

                            if dbj2_hash(&name) == module_name_hash {
                                return Some(dll_base);
                            }
                            name_found = true;
                            break;
                        }
                    }
                }
            }

            if !name_found {}

            if !read_remote(process_handle, ssn_read, current_link, &mut current_link) {
                break;
            }

            if current_link == start_link {
                break;
            }
        }

        None
    }
}

unsafe fn get_module_base_alternative(
    process_handle: *mut c_void,
    module_name_hash: u32,
    ssn_read: u16,
) -> Option<usize> {
    let mut pid: u32 = 0;
    let mut ret_len = 0u32;

    let mut args_pid = [
        process_handle as usize,
        5,
        &mut pid as *mut _ as usize,
        std::mem::size_of::<u32>() as usize,
        &mut ret_len as *mut _ as usize,
    ];
    unsafe {
        let ntdll = get_ntdll_base();
        let ssn_query = get_ssn_by_hash(ntdll, dbj2_hash("NtQueryInformationProcess"))?;
        let status = do_syscall(ssn_query, args_pid.as_mut_ptr());

        if status == 0 {
        } else {
            return None;
        }

        None
    }
}
