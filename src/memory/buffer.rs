use std::ffi::c_void;
use std::mem;

use crate::syscalls::invoker::{SyscallInvoker};
use crate::syscalls::resolver::{get_ssn_by_hash};
use crate::utils::dbj2_hash;

pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

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

pub unsafe fn smart_write(
    invoker:SyscallInvoker,
    ntdll:*mut c_void,
    process_handle: *mut c_void,
    target_address: *mut c_void,
    data: &[u8],
) -> bool {
    unsafe {
        if process_handle.is_null() || target_address.is_null() || data.is_empty() {
            return false;
        }
        if ntdll.is_null() {
            return false;
        }

        let nt_query_hash = dbj2_hash("NtQueryVirtualMemory");
        let nt_protect_hash = dbj2_hash("NtProtectVirtualMemory");
        let nt_write_hash = dbj2_hash("NtWriteVirtualMemory");

        let ssn_query = match get_ssn_by_hash(ntdll, nt_query_hash) {
            Some(ssn) => ssn,
            None => {
                return false;
            }
        };
        let ssn_protect = match get_ssn_by_hash(ntdll, nt_protect_hash) {
            Some(ssn) => ssn,
            None => {
                return false;
            }
        };

        let ssn_write = match get_ssn_by_hash(ntdll, nt_write_hash) {
            Some(ssn) => ssn,
            None => {
                return false;
            }
        };

        let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        let mut args_query = [
            process_handle as usize,
            target_address as usize,
            0,
            &mut mbi as *mut _ as usize,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            0,
        ];
        let query_status = invoker.invoke(ssn_query, args_query.as_mut_ptr());
        if query_status != 0 {
            return false;
        }
        let mut old_protect: u32 = 0;
        let needs_protect =
            (mbi.protect & PAGE_READWRITE) == 0 && (mbi.protect & PAGE_EXECUTE_READWRITE) == 0;

        if needs_protect {
            let mut protect_addr = target_address;
            let mut protect_size = data.len();
            let mut args_protect = [
                process_handle as usize,
                &mut protect_addr as *mut _ as usize,
                &mut protect_size as *mut _ as usize,
                PAGE_EXECUTE_READWRITE as usize,
                &mut old_protect as *mut _ as usize,
            ];
            let protect_status = invoker.invoke(ssn_protect, args_protect.as_mut_ptr());
            if protect_status != 0 {
                return false;
            }
        }

        let mut bytes_written: usize = 0;
        let mut args_write = [
            process_handle as usize,
            target_address as usize,
            data.as_ptr() as usize,
            data.len(),
            &mut bytes_written as *mut _ as usize,
        ];
        let write_status = invoker.invoke(ssn_write, args_write.as_mut_ptr());
        let success = write_status == 0 && bytes_written == data.len();

        if success {
        } else {
        }

        if needs_protect {
            let mut protect_addr = target_address;
            let mut protect_size = data.len();
            let mut junk_protect: u32 = 0;
            let mut args_restore = [
                process_handle as usize,
                &mut protect_addr as *mut _ as usize,
                &mut protect_size as *mut _ as usize,
                old_protect as usize,
                &mut junk_protect as *mut _ as usize,
            ];
            let restore_status = invoker.invoke(ssn_protect, args_restore.as_mut_ptr());
            if restore_status == 0 {
            } else {
            }
        }

        success
    }
}

pub unsafe fn write<T>(invoker:SyscallInvoker,ntdll:*mut c_void,process_handle: *mut c_void, address: usize, value: T) -> bool {
    unsafe {
        let data = std::slice::from_raw_parts(&value as *const T as *const u8, mem::size_of::<T>());
        smart_write(invoker,ntdll,process_handle, address as *mut c_void, data)
    }
}

pub unsafe fn read_buffer(invoker:SyscallInvoker,ntdll:*mut c_void,process_handle: *mut c_void, address: usize, buffer: &mut [u8]) -> bool {
    unsafe {
        let ssn_read = get_ssn_by_hash(ntdll, dbj2_hash("NtReadVirtualMemory")).unwrap();

        let mut bytes_read: usize = 0;
        let mut args = [
            process_handle as usize,
            address,
            buffer.as_mut_ptr() as usize,
            buffer.len(),
            &mut bytes_read as *mut usize as usize,
        ];

        let status = invoker.invoke(ssn_read, args.as_mut_ptr());
        status == 0 && bytes_read == buffer.len()
    }
}

pub unsafe fn read_bytes(invoker:SyscallInvoker,ntdll:*mut c_void,process_handle: *mut c_void, address: usize, size: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; size];
    let succes = unsafe { read_buffer(invoker,ntdll,process_handle, address, &mut buffer) };
    if succes { buffer } else { Vec::new() }
}

pub unsafe fn read<T>(invoker:SyscallInvoker, ntdll:*mut c_void,process_handle: *mut c_void, address: usize) -> T {
    unsafe {
        let mut buffer: T = mem::zeroed();
        let ssn_read = get_ssn_by_hash(ntdll, dbj2_hash("NtReadVirtualMemory")).unwrap();

        let mut bytes_read: usize = 0;
        let mut args = [
            process_handle as usize,
            address,
            &mut buffer as *mut T as usize,
            mem::size_of::<T>(),
            &mut bytes_read as *mut usize as usize,
        ];

        invoker.invoke(ssn_read, args.as_mut_ptr());
        buffer
    }
}
