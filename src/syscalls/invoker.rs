use std::arch::asm;
use std::ffi::c_void;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub struct Gadget {
    pub addr: usize,
    pub size: usize,
}

#[repr(C)]
pub struct SyscallConfig {
    pub jump_address: usize,
    pub return_address: usize,
    pub nargs: usize,
    pub args: [usize; 11],
    pub ssn: u32,
}

pub unsafe fn find_all_syscall_stub_pattern(
    ntdll_base: *mut c_void,
    ntdll_size: usize,
) -> Vec<usize> {
    unsafe {
        //0x0f 0x05 (syscall)
        let matches = crate::memory::scanner::pattern_scan_all_local(
            ntdll_base as usize,
            ntdll_size,
            "0F 05 C3",
        );
        matches
    }
}
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
unsafe fn find_suitable_gadgets(ntdll_base: *mut c_void, ntdll_size: usize) -> Vec<Gadget> {
    let mut list = Vec::new();

    let mut matches = crate::memory::scanner::pattern_scan_all_local(
        ntdll_base as usize,
        ntdll_size,
        "48 83 C4 ? C3",
    );
    let matchesx = crate::memory::scanner::pattern_scan_all_local(
        ntdll_base as usize,
        ntdll_size,
        "48 83 C4 ? ? ? C3",
    );

    for ma in matchesx {
        matches.push(ma);
    }

    for addr in matches {
        let size = *((addr + 3) as *const u8) as usize;
        if size >= 0x10 && size <= 0x40 && size % 8 == 0 {
            list.push(Gadget { addr, size });
        }
    }

    list
}
fn build_rop_chain(available: &[Gadget], target: usize) -> Vec<Gadget> {
    let mut chain = Vec::new();
    let mut total = 0;
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as usize;
    let mut sorted = available.to_vec();
    sorted.sort_by(|a, b| b.size.cmp(&a.size)); 

    for g in sorted.iter() {
        if total + g.size + 8 > target {
            continue;
        }
        chain.push(*g);
        total += g.size + 8;
        if total >= target {
            break;
        }
    }
    while total < target {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(12345);
        let idx = (seed >> 16) % available.len();
        let g = &available[idx];
        if total + g.size + 8 <= target {
            chain.push(*g);
            total += g.size + 8;
        } else {
            break;
        }
    }

    chain
}

pub unsafe fn get_legit_paddings(ntdll_base: *mut c_void, ntdll_size: usize) -> Vec<usize> {
    let mut paddings = Vec::new();

    // "C3" (ret)
    let ret_gadgets =
        crate::memory::scanner::pattern_scan_all_local(ntdll_base as usize, ntdll_size, "C3");

    // "CC" (int3)
    let int3_gadgets =
        crate::memory::scanner::pattern_scan_all_local(ntdll_base as usize, ntdll_size, "CC");

    for addr in ret_gadgets.iter().chain(int3_gadgets.iter()) {
        paddings.push(*addr);
    }
    paddings.sort();
    paddings.dedup();
    paddings
}

pub fn prepare_rop_stack(
    chain: &[Gadget],
    paddings: &[usize],
    syscall_stack_size: usize,
) -> Vec<usize> {
    let mut stack = Vec::new();
    //println!("chains: {:?}", chain);
    let use_deadbeef = paddings.is_empty();
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as usize;
    for g in chain.iter().rev() {
        let padding_slots = (g.size / 8) - 1;
        for _ in 0..padding_slots {
            if use_deadbeef {
                stack.push(0xDEADBEEFDEADBEEF);
            } else {
                seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                let idx = (seed >> 16) % paddings.len();
                stack.push(paddings[idx]);
            }
        }
        stack.push(g.addr);

        // let total_slots = (g.size + 8) / 8;

        // for _ in 1..total_slots {
        //     stack.push(0x4141414141414141);
        // }
    }
    let slots = syscall_stack_size / 8;
    for _ in 0..slots {
        stack.push(0);
    }
    stack
}

pub unsafe fn get_return_address() -> usize {
    let mut return_addr = 0;
    unsafe {
        asm!(
            "lea {0}, [rip + 2f]", 
            out(reg) return_addr
        );
    }
    return_addr
}
pub unsafe fn indirect_syscall_rop(
    ssn: u16,
    syscall_addr: *mut c_void,
    stack_image: Vec<usize>,
    args: *mut usize,
) -> u32 {
    let mut status: u32;
    let return_addr: usize = get_return_address();
    let mut stack: Vec<usize> = Vec::new(); 
    stack.push(return_addr); // dönüş adresi en tepede olacak. (high to low)
    for a in stack_image {
        stack.push(a); // stacki doldur
    }
    // println!(
    //     "SSN {:?} - SYSCALL ADDR: {:?} - STACKIMAGE {:?}  - ARGS {:?}",
    //     ssn, syscall_addr, stack, args
    // );
    let stack_top = stack.as_ptr();
    unsafe {
        asm!(
        "mov r12, rsp",             // dönüş adresini al
        "mov rsp, {stack_ptr}",     // stacki doldur
        "mov r11, {args}",          // argümanları al (ilk 4 ü rcx rdx r8 r9 gerisi stack - winx64 abi)
        "mov rcx, [r11 + 0]",       // 1. arg rcx
        "mov rdx, [r11 + 8]",       // 2. arg rdx
        "mov r8,  [r11 + 16]",      // 3. arg r8
        "mov r9,  [r11 + 24]",      // 4. arg r9
        "mov rax, [r11 + 32]",      // 5. arg al
        "mov [rsp + 32], rax",      // 5. arg stack
        "mov rax, [r11 + 40]",      // 6. arg al
        "mov [rsp + 40], rax",      // 6. arg stack
        "mov rax, [r11 + 48]",      // 7. arg al
        "mov [rsp + 48], rax",      // 7. arg stack
        "mov rax, [r11 + 56]",      // 8. arg al
        "mov [rsp + 56], rax",      // 8.arg stack
        "mov rax, [r11 + 64]",      // 9. arg al
        "mov [rsp + 64], rax",      // 9. arg stack
        "mov rax, [r11 + 72]",      // 10. arg al
        "mov [rsp + 72], rax",      // 10. arg stack
        "mov r10, rcx",             // syscall hazırlığı
        "mov eax, {ssn:e}",         // ssn i yaz
        "jmp {syscall}",            // syscall stuba atla
        "2:",                       // label 2
        "mov {status:e}, eax",      // nstatusı al
        "mov rsp, r12",             // dön.
        stack_ptr = in(reg) stack_top,
        syscall = in(reg) syscall_addr,
        args = in(reg) args,
        ssn = in(reg) ssn,
         status = out(reg) status,
         out("r12") _,
         out("rax") _, out("rcx") _, out("rdx") _,
        out("r8") _, out("r9") _, out("r10") _, out("r11") _
            );
        status
    }
}
pub unsafe fn indirect_syscall(ssn: u16, syscall_addr: *mut c_void, args: *mut usize) -> u32 {
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
            "add rsp, 96",              // temizlik
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

#[derive(Debug, Clone)]
pub struct SyscallInvoker {
    syscall_stub: *mut c_void,
    gadgets: Vec<Gadget>,
    paddings: Vec<usize>,
}

impl SyscallInvoker {
    pub unsafe fn new(ntdll_base: *mut c_void, ntdll_size: usize) -> Option<Self> {
        let syscalls = find_all_syscall_stub_pattern(ntdll_base, ntdll_size);
        //println!("syscall list {:?}", syscalls);
        let syscall_stub = if !syscalls.is_empty() {
            let index = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos()
                % syscalls.len() as u128) as usize;
            syscalls[index] as *mut c_void
        } else {
            find_syscall_stub_pattern(ntdll_base, ntdll_size)?
        };
        //println!("syscall {:?}", syscall_stub);
        let gadgets = find_suitable_gadgets(ntdll_base, ntdll_size);
        //println!("gadgets {:?}", gadgets);
        let legit_paddings = get_legit_paddings(ntdll_base, ntdll_size);
        //println!("paddings {:?}", legit_paddings);
        Some(Self {
            syscall_stub: syscall_stub,
            gadgets: gadgets,
            paddings: legit_paddings,
        })
    }

    pub unsafe fn invoke(&self, ssn: u16, args: *mut usize) -> u32 {
        let syscall_stack_size = 0x80;
        let chain = build_rop_chain(&self.gadgets, 0x80);
        let mut stack = prepare_rop_stack(&chain, &self.paddings, syscall_stack_size);
        if (stack.len() * 8) % 16 != 0 {
            stack.push(0);
        }
        unsafe { indirect_syscall_rop(ssn, self.syscall_stub, stack, args) }
        //unsafe { indirect_syscall(ssn, self.syscall_stub, args) }
    }
}
