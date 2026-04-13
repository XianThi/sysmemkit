use std::arch::asm;
use std::ffi::c_void;

pub unsafe fn find_syscall_stub_pattern(
    ntdll_base: *mut c_void,
    ntdll_size: usize,
) -> Option<*mut c_void> {
    if ntdll_base.is_null() {
        return None;
    }
    unsafe {
        
        //0x0f 0x05 (syscall)
        if let Some(addr) =
            crate::memory::scanner::pattern_scan_local(ntdll_base as usize, ntdll_size, "0F 05 C3")
        {
            return Some(addr as *mut c_void);
        }

        // 0xB8 ?? ?? ?? ?? 0x0F 0x05 (mov eax, SSN; syscall)
        if let Some(addr) = crate::memory::scanner::pattern_scan_local(
            ntdll_base as usize,
            ntdll_size,
            "B8 ? ? ? ? 0F 05",
        ) {
            return Some((addr + 5) as *mut c_void);
        }

        // 0x4C 0x8B 0xD1 0xB8 ?? ?? ?? ?? 0x0F 0x05 (mov r10, rcx; mov eax, SSN; syscall)
        if let Some(addr) = crate::memory::scanner::pattern_scan_local(
            ntdll_base as usize,
            ntdll_size,
            "4C 8B D1 B8 ? ? ? ? 0F 05",
        ) {
            return Some((addr + 8) as *mut c_void);
        }

        if let Some(addr) = crate::memory::scanner::pattern_scan_local(
            ntdll_base as usize,
            ntdll_size,
            "B8 ? ? ? ? 0F 05 C3",
        ) {
            return Some((addr + 5) as *mut c_void);
        }
    }
    None
}

pub unsafe fn indirect_syscall(
    ssn: u16,
    syscall_addr: *mut c_void,
    args: *mut usize
) -> u32 {
    let mut status: u32;
    
    unsafe {
        asm!(
            "sub rsp, 96",              // 96 byte shadow space (winx64 abi 16-byte aligment)
            "mov r10, {args}",          // args pointer'ını r10'a al
            "mov rcx, [r10 + 0]",       //1. parametreyi rcx
            "mov rdx, [r10 + 8]",       //2. parametreyi rdx
            "mov r8,  [r10 + 16]",      //3. parametreyi r8
            "mov r9,  [r10 + 24]",      //4. parametreyi r9

            "mov rax, [r10 + 32]",      //5. parametreyi oku
            "mov [rsp + 32], rax",      // Stack'e yaz
            "mov rax, [r10 + 40]",      //6. parametreyi oku
            "mov [rsp + 40], rax",      // Stack'e yaz
            "mov rax, [r10 + 48]",      //7. parametreyi oku
            "mov [rsp + 48], rax",      // Stack'e yaz
            "mov rax, [r10 + 56]",      //8. parametreyi oku
            "mov [rsp + 56], rax",      // Stack'e yaz
            "mov rax, [r10 + 64]",      //9. parametreyi oku
            "mov [rsp + 64], rax",      // Stack'e yaz
            "mov rax, [r10 + 72]",      //10. parametreyi oku
            "mov [rsp + 72], rax",      // Stack'e yaz

            "mov r10, rcx",             // alignment
            "mov eax, {ssn:e}",         // Syscall icin ssn
            "xor r11, r11",             // junk
            "inc r11",                  // junk
            "call {addr}",              // Indirect syscall
            "add rsp, 80",              // temizlik
            "mov {status}, rax",
            
            addr = in(reg) syscall_addr,
            args = in(reg) args,
            ssn = in(reg) ssn,
            status = out(reg) status,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("rax") _,
            out("r11") _,
            //options(nostack)
        );
        
        status
    }
}

pub unsafe fn do_syscall(ssn: u16, args: *mut usize) -> u32 {
    let mut status: u32;
    unsafe {
        asm!(
            "mov r11, {args}",      // args pointer'ını r11'e al
            "mov rcx, [r11 + 0]",   //1. parametreyi rcx
            "mov rdx, [r11 + 8]",   //2. parametreyi rdx
            "mov r8,  [r11 + 16]",  //3. parametreyi r8
            "mov r9,  [r11 + 24]",  //4. parametreyi r9
            "mov rax, [r11 + 32]",  // 5. parametreyi args'tan oku
            "mov [rsp + 40], rax",  // Stack'e yaz
            "mov rax, [r11 + 40]",  // 6. parametreyi args'tan oku
            "mov [rsp + 48], rax",  // Stack'e yaz
            "mov r10, rcx",         // alignment
            "mov eax, {ssn:e}",     // Syscall icin ssn
            "xor r11, r11",         // junk
            "inc r11",              // junk
            "syscall",
            lateout("rax") status,
            args = in(reg) args,
            ssn = in(reg) ssn,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack)
        );

        status
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SyscallInvoker {
    syscall_stub: *mut c_void,
}

impl SyscallInvoker {
    pub unsafe fn new(ntdll_base: *mut c_void, ntdll_size: usize) -> Option<Self> {
        let syscall_stub = unsafe { find_syscall_stub_pattern(ntdll_base, ntdll_size)? };
        Some(Self { syscall_stub })
    }

    pub unsafe fn invoke(&self, ssn: u16, args: *mut usize) -> u32 {
        unsafe { indirect_syscall(ssn, self.syscall_stub, args) }
    }
}
