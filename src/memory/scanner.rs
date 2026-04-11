use crate::syscalls::invoker::do_syscall;
use crate::syscalls::resolver::{get_ntdll_base, get_ssn_by_hash};
use crate::utils::dbj2_hash;
use std::ffi::c_void;
pub unsafe fn pattern_scan(
    process_handle: *mut c_void,
    start: usize,
    size: usize,
    pattern: &str,
) -> Option<usize> {
    unsafe {
        let mut buffer = vec![0u8; size];
        let ntdll = get_ntdll_base();
        let ssn_read = get_ssn_by_hash(ntdll, dbj2_hash("NtReadVirtualMemory")).unwrap();

        let mut br = 0;
        let mut args = [
            process_handle as usize,
            start,
            buffer.as_mut_ptr() as usize,
            size,
            &mut br as *mut _ as usize,
        ];
        do_syscall(ssn_read, args.as_mut_ptr());

        let pattern_bytes: Vec<Option<u8>> = pattern
            .split_whitespace()
            .map(|b| {
                if b == "?" {
                    None
                } else {
                    Some(u8::from_str_radix(b, 16).unwrap())
                }
            })
            .collect();

        for i in 0..(size - pattern_bytes.len()) {
            let mut found = true;
            for (j, byte) in pattern_bytes.iter().enumerate() {
                if let Some(b) = byte {
                    if buffer[i + j] != *b {
                        found = false;
                        break;
                    }
                }
            }
            if found {
                return Some(start + i);
            }
        }
        None
    }
}
