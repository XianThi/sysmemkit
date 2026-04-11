use std::arch::asm;

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
