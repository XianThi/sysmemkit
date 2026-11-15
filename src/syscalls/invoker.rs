use std::arch::asm;
use std::ffi::c_void;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "rage")]
use crate::include::def::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_NT_SIGNATURE,
    RUNTIME_FUNCTION,
};

#[cfg(feature = "rage")]
#[derive(Debug, Clone, Copy)]
pub struct Gadget {
    pub addr: usize,
    pub size: usize,
}

// Faz 1'de `Mode` altyapısında kullanılacak; şimdilik iskelet.
#[allow(dead_code)]
#[repr(C)]
pub struct SyscallConfig {
    pub jump_address: usize,
    pub return_address: usize,
    pub nargs: usize,
    pub args: [usize; 11],
    pub ssn: u32,
}

/// ntdll içinde `syscall; ret` pattern'ine uyan tüm adresleri bulur.
///
/// # Safety
///
/// `ntdll_base` ve `ntdll_size` geçerli bir ntdll PE haritasını göstermelidir.
pub unsafe fn find_all_syscall_stub_pattern(
    ntdll_base: *mut c_void,
    ntdll_size: usize,
) -> Vec<usize> {
    unsafe {
        // 0x0f 0x05 (syscall)
        crate::memory::scanner::pattern_scan_all_local(
            ntdll_base as usize,
            ntdll_size,
            "0F 05 C3",
        )
    }
}

/// ntdll içinde meşru bir `syscall; ret` stub adresi döner.
///
/// # Safety
///
/// `ntdll_base` ve `ntdll_size` geçerli bir ntdll PE haritasını göstermelidir.
pub unsafe fn find_syscall_stub_pattern(
    ntdll_base: *mut c_void,
    ntdll_size: usize,
) -> Option<*mut c_void> {
    if ntdll_base.is_null() {
        return None;
    }
    unsafe {
        // 0x0f 0x05 (syscall)
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

#[cfg(feature = "rage")]
unsafe fn get_runtime_functions(ntdll_base: *mut c_void, ntdll_size: usize) -> &'static [RUNTIME_FUNCTION] {
    if ntdll_base.is_null() || ntdll_size < 0x1000 {
        return &[];
    }
    let dos = ntdll_base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE {
        return &[];
    }
    let nt_offset = (*dos).e_lfanew as usize;
    if nt_offset + std::mem::size_of::<IMAGE_NT_HEADERS64>() > ntdll_size {
        return &[];
    }
    let nt = (ntdll_base as usize + nt_offset) as *const IMAGE_NT_HEADERS64;
    if (*nt).signature != IMAGE_NT_SIGNATURE {
        return &[];
    }
    // Exception directory is index 3
    let exc_dir = &(*nt).optional_header.data_directory[3];
    if exc_dir.virtual_address == 0 || exc_dir.size == 0 {
        return &[];
    }
    let exc_rva = exc_dir.virtual_address as usize;
    let exc_size = exc_dir.size as usize;
    if exc_rva + exc_size > ntdll_size {
        return &[];
    }
    let count = exc_size / std::mem::size_of::<RUNTIME_FUNCTION>();
    let ptr = (ntdll_base as usize + exc_rva) as *const RUNTIME_FUNCTION;
    std::slice::from_raw_parts(ptr, count)
}

#[cfg(feature = "rage")]
unsafe fn is_valid_unwind_epilogue(
    ntdll_base: *mut c_void,
    gadget_addr: usize,
    gadget_len: usize,
    runtime_funcs: &[RUNTIME_FUNCTION],
) -> bool {
    let base_val = ntdll_base as usize;
    if gadget_addr < base_val {
        return false;
    }
    let rva = (gadget_addr - base_val) as u32;

    let match_res = runtime_funcs.binary_search_by(|rf| {
        if rva < rf.begin_address {
            std::cmp::Ordering::Greater
        } else if rva >= rf.end_address {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    });

    if let Ok(idx) = match_res {
        let rf = &runtime_funcs[idx];
        let gadget_end = rva + gadget_len as u32;
        if gadget_end <= rf.end_address && rf.end_address - gadget_end <= 8 {
            return true;
        }
    }
    false
}

#[cfg(feature = "rage")]
unsafe fn find_suitable_gadgets(ntdll_base: *mut c_void, ntdll_size: usize) -> Vec<Gadget> {
    if ntdll_base.is_null() || ntdll_size == 0 {
        return Vec::new();
    }
    let mut list = Vec::new();
    let runtime_funcs = unsafe { get_runtime_functions(ntdll_base, ntdll_size) };

    // 1. Birincil tercih: "48 83 C4 68 C3" (add rsp, 0x68; ret)
    let matches_68 = crate::memory::scanner::pattern_scan_all_local(
        ntdll_base as usize,
        ntdll_size,
        "48 83 C4 68 C3",
    );
    for addr in matches_68 {
        if unsafe { is_valid_unwind_epilogue(ntdll_base, addr, 5, runtime_funcs) } {
            list.push(Gadget { addr, size: 0x68 });
        }
    }

    // 2. İkincil adaylar: 0x58..=0x78 aralığındaki 8'in katı olan diğer add rsp, imm8; ret gadget'ları
    let matches_gen = crate::memory::scanner::pattern_scan_all_local(
        ntdll_base as usize,
        ntdll_size,
        "48 83 C4 ? C3",
    );
    for addr in matches_gen {
        let size = unsafe { *((addr + 3) as *const u8) } as usize;
        if (0x58..=0x78).contains(&size)
            && size.is_multiple_of(8)
            && size != 0x68
            && unsafe { is_valid_unwind_epilogue(ntdll_base, addr, 5, runtime_funcs) }
        {
            list.push(Gadget { addr, size });
        }
    }

    list
}

#[cfg(feature = "rage")]
/// ntdll içindeki meşru fonksiyon sonu (epilogue) `ret` (0xC3) adreslerini toplar.
///
/// Komut ortasındaki rasgele `C3`/`CC` baytlarını eler; yalnızca `.pdata` çalışma zamanı
/// fonksiyon tabloları tarafından teyit edilmiş meşru fonksiyon bitiş adreslerini döner.
///
/// # Safety
///
/// `ntdll_base` ve `ntdll_size` geçerli bir ntdll PE haritasını göstermelidir.
pub unsafe fn get_legit_paddings(ntdll_base: *mut c_void, ntdll_size: usize) -> Vec<usize> {
    if ntdll_base.is_null() || ntdll_size == 0 {
        return Vec::new();
    }
    let mut paddings = Vec::new();
    let runtime_funcs = unsafe { get_runtime_functions(ntdll_base, ntdll_size) };

    for rf in runtime_funcs {
        if rf.end_address > rf.begin_address {
            let ret_rva = (rf.end_address - 1) as usize;
            if ret_rva < ntdll_size {
                let ret_addr = ntdll_base as usize + ret_rva;
                if unsafe { *(ret_addr as *const u8) } == 0xC3 {
                    paddings.push(ret_addr);
                }
            }
        }
    }

    paddings.sort_unstable();
    paddings.dedup();
    paddings
}

#[cfg(feature = "rage")]
/// Geçerli çağrı çerçevesinin dönüş adresini döner.
///
/// # Safety
///
/// Yalnızca x86_64 mimarisinde çağrılmalıdır.
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

#[cfg(feature = "rage")]
/// ROP zinciri ile dolaylı sistem çağrısı yapar (Faz 4 öncesi devre dışı / deneysel).
///
/// # Safety
///
/// `syscall_addr` geçerli bir syscall gadget'ı olmalı, `args` geçerli argüman dizisine işaret etmelidir.
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
            "mov [rsp + 40], rax",      // 5. arg stack
            "mov rax, [r11 + 40]",      // 6. arg al
            "mov [rsp + 48], rax",      // 6. arg stack
            "mov rax, [r11 + 48]",      // 7. arg al
            "mov [rsp + 56], rax",      // 7. arg stack
            "mov rax, [r11 + 56]",      // 8. arg al
            "mov [rsp + 64], rax",      // 8. arg stack
            "mov rax, [r11 + 64]",      // 9. arg al
            "mov [rsp + 72], rax",      // 9. arg stack
            "mov rax, [r11 + 72]",      // 10. arg al
            "mov [rsp + 80], rax",      // 10. arg stack
            "mov r10, rcx",             // syscall hazırlığı
            "mov eax, {ssn:e}",         // ssn i yaz
            "jmp {syscall}",            // syscall stuba atla
            "2:",                       // label 2
            "mov {status:e}, eax",      // ntstatusı al
            "mov rsp, r12",             // dön.
            stack_ptr = in(reg) stack_top,
            syscall = in(reg) syscall_addr,
            args = in(reg) args,
            ssn = in(reg) u32::from(ssn),
            status = out(reg) status,
            out("r12") _,
            out("rax") _, out("rcx") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _
        );
        status
    }
}

/// Dolaylı sistem çağrısı yürütür (Faz 3 varsayılan çağırma yolu).
///
/// x64 ABI uyumlu 96 baytlık yığın çerçevesi ayrılır; ilk 4 parametre register'lara (`r10, rdx, r8, r9`),
/// kalan 6 parametre `[rsp + 32..rsp + 72]` aralığına yerleştirilir. `call` talimatı 8 baytlık dönüş
/// adresini yığına ittiğinde parametreler kernel'ın beklediği `[rsp + 0x28..0x50]` konumlarına hizalanır.
///
/// # Safety
///
/// `syscall_addr` ntdll içinde meşru bir `syscall; ret` talimatını göstermeli, `args` geçerli
/// argümanları içermelidir.
pub unsafe fn indirect_syscall(ssn: u16, syscall_addr: *mut c_void, args: *mut usize) -> u32 {
    let mut status: u32;

    unsafe {
        asm!(
            "push rbx",
            "push rsi",
            "push rdi",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "sub rsp, 96",

            "mov rsi, r12",
            "mov rcx, [rsi + 0]",
            "mov rdx, [rsi + 8]",
            "mov r8,  [rsi + 16]",
            "mov r9,  [rsi + 24]",
            "mov rax, [rsi + 32]",
            "mov [rsp + 32], rax",
            "mov rax, [rsi + 40]",
            "mov [rsp + 40], rax",
            "mov rax, [rsi + 48]",
            "mov [rsp + 48], rax",
            "mov rax, [rsi + 56]",
            "mov [rsp + 56], rax",
            "mov rax, [rsi + 64]",
            "mov [rsp + 64], rax",
            "mov rax, [rsi + 72]",
            "mov [rsp + 72], rax",

            "mov r10, rcx",
            "mov eax, r13d",
            "call r11",

            "add rsp, 96",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rdi",
            "pop rsi",
            "pop rbx",

            in("r11") syscall_addr,
            in("r12") args,
            in("r13") u32::from(ssn),
            lateout("eax") status,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
        );

        status
    }
}

/// Doğrudan syscall: `mov r10, rcx; mov eax, ssn; syscall`.
///
/// # Safety
///
/// `ssn` çağrılan Nt* fonksiyonunun numarası olmalı ve `args` en az o fonksiyonun beklediği
/// sayıda argüman içeren bir diziye işaret etmelidir. Syscall çağıranın bağlamında, tam
/// yetkiyle çalışır; yanlış SSN süreci bozabilir.
pub unsafe fn do_syscall(ssn: u16, args: *mut usize) -> u32 {
    let mut status: u32;
    unsafe {
        asm!(
            "push rbx",
            "push rsi",
            "push rdi",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "sub rsp, 104",

            "mov rsi, r12",
            "mov rcx, [rsi + 0]",
            "mov rdx, [rsi + 8]",
            "mov r8,  [rsi + 16]",
            "mov r9,  [rsi + 24]",
            "mov rax, [rsi + 32]",
            "mov [rsp + 40], rax",
            "mov rax, [rsi + 40]",
            "mov [rsp + 48], rax",
            "mov rax, [rsi + 48]",
            "mov [rsp + 56], rax",
            "mov rax, [rsi + 56]",
            "mov [rsp + 64], rax",
            "mov rax, [rsi + 64]",
            "mov [rsp + 72], rax",
            "mov rax, [rsi + 72]",
            "mov [rsp + 80], rax",

            "mov r10, rcx",
            "mov eax, r13d",
            "syscall",

            "add rsp, 104",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r12",
            "pop rdi",
            "pop rsi",
            "pop rbx",

            in("r12") args,
            in("r13") u32::from(ssn),
            lateout("eax") status,
            out("rcx") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
        );
    }
    status
}

/// Sistem çağrılarını yürütmek için soyut arayüz (Faz 1).
pub trait SyscallInvoker: Send + Sync {
    /// 11 elemanlı argüman dizisiyle sistem çağrısını yürütür.
    ///
    /// # Safety
    ///
    /// `ssn` geçerli bir NT syscall numarası olmalı ve `args` doğru parametreleri içermelidir.
    unsafe fn invoke(&self, ssn: u16, stub: usize, args: &mut [usize; 11]) -> u32;

    /// İnvoker türünün açıklayıcı adını döner.
    fn name(&self) -> &'static str;
}

/// Mode::Basic ve Mode::DirectStealth için doğrudan `syscall` komutunu çalıştıran çağırıcı.
#[derive(Debug, Default, Clone, Copy)]
pub struct DirectInvoker;

impl SyscallInvoker for DirectInvoker {
    unsafe fn invoke(&self, ssn: u16, _stub: usize, args: &mut [usize; 11]) -> u32 {
        unsafe { do_syscall(ssn, args.as_mut_ptr()) }
    }

    fn name(&self) -> &'static str {
        "Direct"
    }
}

/// Mode::Indirect için hedef stub'daki meşru `syscall; ret` adresine `call` ile atlayan çağırıcı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndirectInvoker {
    pub fallback_stub: usize,
}

impl IndirectInvoker {
    /// ntdll tabanından bir meşru `syscall; ret` adresi bularak varsayılan indirect invoker oluşturur.
    ///
    /// # Safety
    ///
    /// `ntdll_base` ve `ntdll_size` geçerli bir ntdll PE haritasını göstermelidir.
    pub unsafe fn new(ntdll_base: *mut c_void, ntdll_size: usize) -> Self {
        let fallback = unsafe {
            find_syscall_stub_pattern(ntdll_base, ntdll_size)
                .map(|p| p as usize)
                .unwrap_or(0)
        };
        Self {
            fallback_stub: fallback,
        }
    }
}

impl SyscallInvoker for IndirectInvoker {
    unsafe fn invoke(&self, ssn: u16, stub: usize, args: &mut [usize; 11]) -> u32 {
        let target_stub = if stub != 0 {
            stub
        } else {
            self.fallback_stub
        };
        if target_stub == 0 {
            return 0xC000000D; // STATUS_INVALID_PARAMETER
        }
        unsafe { indirect_syscall(ssn, target_stub as *mut c_void, args.as_mut_ptr()) }
    }

    fn name(&self) -> &'static str {
        "Indirect"
    }
}

/// Rastgele `syscall; ret` gadget'ı seçerek dolaylı sistem çağrısı yapan çağırıcı.
#[derive(Debug, Clone)]
pub struct RandomizerInvoker {
    pub stubs: Vec<usize>,
    pub fallback_stub: usize,
}

impl RandomizerInvoker {
    /// ntdll tabanından tüm `0F 05 C3` gadget'larını toplayarak invoker oluşturur.
    ///
    /// # Safety
    ///
    /// `ntdll_base` ve `ntdll_size` geçerli bir ntdll PE haritasını göstermelidir.
    pub unsafe fn new(ntdll_base: *mut c_void, ntdll_size: usize) -> Self {
        let stubs = unsafe { find_all_syscall_stub_pattern(ntdll_base, ntdll_size) };
        let fallback = stubs.first().copied().unwrap_or(0);
        Self {
            stubs,
            fallback_stub: fallback,
        }
    }
}

impl SyscallInvoker for RandomizerInvoker {
    unsafe fn invoke(&self, ssn: u16, stub: usize, args: &mut [usize; 11]) -> u32 {
        let target_stub = if !self.stubs.is_empty() {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let idx = (nanos % self.stubs.len() as u128) as usize;
            self.stubs[idx]
        } else if stub != 0 {
            stub
        } else {
            self.fallback_stub
        };

        if target_stub == 0 {
            return 0xC000000D; // STATUS_INVALID_PARAMETER
        }

        unsafe { indirect_syscall(ssn, target_stub as *mut c_void, args.as_mut_ptr()) }
    }

    fn name(&self) -> &'static str {
        "Randomizer"
    }
}


/// Gerçek thread stack'i (`rsp`) üzerinde çalışan trampoline ile dolaylı syscall çağrısı (Faz 4).
///
/// Heap pivot yapmaz; doğrudan çağrıyı yapan iş parçacığının yığını üzerinde 120 baytlık (0x78)
/// kontrollü bir çerçeve açar.
///
/// Yığın Çerçevesi Düzeni (0x78 bayt):
/// - `[rsp + 0x00]`: Gadget adresi (`add rsp, 0x68; ret` — ntdll .pdata içinde meşru epilog)
/// - `[rsp + 0x08..0x28]`: Shadow Space (32 bayt)
/// - `[rsp + 0x28..0x58]`: 5. ila 10. syscall argümanları (48 bayt)
/// - `[rsp + 0x58..0x68]`: Hizalama / yerel alan (16 bayt)
/// - `[rsp + 0x70]`: Dönüş adresi (`2:` yerel etiketi)
///
/// Çağrı Akışı:
/// 1. `sub rsp, 0x78` ile gerçek yığında çerçeve açılır.
/// 2. `2:` etiketinin adresi `[rsp + 0x70]` konumuna yazılır.
/// 3. `[rsp + 0x00]` konumuna unwind tablosunca doğrulanmış gadget adresi yazılır.
/// 4. 5..10. argümanlar `[rsp + 0x28..0x58]` aralığına yerleştirilir.
/// 5. Kayıtlar Windows x64 çağrı kuralına göre yüklenir (`r10=arg1, rdx=arg2, r8=arg3, r9=arg4, eax=ssn`).
/// 6. `jmp syscall_addr` ile doğrudan ntdll stub'ındaki `syscall` talimatına zıplanır.
/// 7. Çekirdek dönüşünde ntdll'deki `ret` komutu yığının tepesindeki (`[rsp + 0x00]`) gadget'a zıplar (`rsp += 8`).
/// 8. Gadget `add rsp, 0x68; ret` talimatını yürütür (`rsp += 0x68`, yani `0x08 + 0x68 = 0x70` olur).
/// 9. Gadget'ın `ret` komutu `[rsp + 0x70]` konumundaki `2:` etiketine döner (`rsp += 8`, yani `0x78` olur).
/// 10. Yığın tam olarak `sub rsp, 0x78` öncesindeki başlangıç değerine kavuşur.
///
/// # Safety
///
/// `syscall_addr` ntdll içinde meşru bir `syscall` talimatını göstermeli, `gadget_addr`
/// `add rsp, 0x68; ret` epiloguna ait olmalı ve `args` 10 argüman içeren geçerli bir dizi olmalıdır.
#[cfg(target_arch = "x86_64")]
pub unsafe fn indirect_syscall_trampoline(
    ssn: u16,
    syscall_addr: *mut c_void,
    gadget_addr: usize,
    args: *mut usize,
) -> u32 {
    let mut status: u32;
    unsafe {
        asm!(
            "sub rsp, 0x78",
            "lea rax, [rip + 2f]",
            "mov [rsp + 0x70], rax",
            "mov [rsp + 0x00], {gadget}",
            "mov r11, {args}",
            "mov rax, [r11 + 32]",
            "mov [rsp + 0x28], rax",
            "mov rax, [r11 + 40]",
            "mov [rsp + 0x30], rax",
            "mov rax, [r11 + 48]",
            "mov [rsp + 0x38], rax",
            "mov rax, [r11 + 56]",
            "mov [rsp + 0x40], rax",
            "mov rax, [r11 + 64]",
            "mov [rsp + 0x48], rax",
            "mov rax, [r11 + 72]",
            "mov [rsp + 0x50], rax",
            "mov rcx, [r11 + 0]",
            "mov rdx, [r11 + 8]",
            "mov r8,  [r11 + 16]",
            "mov r9,  [r11 + 24]",
            "mov r10, rcx",
            "mov eax, {ssn:e}",
            "jmp {target}",
            "2:",
            "mov {status:e}, eax",
            gadget = in(reg) gadget_addr,
            args = in(reg) args,
            ssn = in(reg) u32::from(ssn),
            target = in(reg) syscall_addr,
            status = out(reg) status,
            out("rax") _, out("rcx") _, out("rdx") _,
            out("r8") _, out("r9") _, out("r10") _, out("r11") _
        );
        status
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn indirect_syscall_trampoline(
    _ssn: u16,
    _syscall_addr: *mut c_void,
    _gadget_addr: usize,
    _args: *mut usize,
) -> u32 {
    0xC0000001
}

/// Mode::Rage için meşru yığın üzerinde trampoline ve .pdata doğrulamalı gadget'lar kullanan çağırıcı.
#[cfg(feature = "rage")]
#[derive(Debug, Clone)]
pub struct RopInvoker {
    pub syscall_stub: *mut c_void,
    pub gadgets: Vec<Gadget>,
    pub paddings: Vec<usize>,
}

#[cfg(feature = "rage")]
unsafe impl Send for RopInvoker {}
#[cfg(feature = "rage")]
unsafe impl Sync for RopInvoker {}

#[cfg(feature = "rage")]
impl RopInvoker {
    /// ntdll tabanından .pdata doğrulamalı ROP gadget'larını ve meşru syscall stub'larını toplayarak invoker oluşturur.
    ///
    /// # Safety
    ///
    /// `ntdll_base` ve `ntdll_size` geçerli bir ntdll PE haritasını göstermelidir.
    pub unsafe fn new(ntdll_base: *mut c_void, ntdll_size: usize) -> Option<Self> {
        let syscalls = find_all_syscall_stub_pattern(ntdll_base, ntdll_size);
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
        let gadgets = find_suitable_gadgets(ntdll_base, ntdll_size);
        let legit_paddings = get_legit_paddings(ntdll_base, ntdll_size);
        Some(Self {
            syscall_stub,
            gadgets,
            paddings: legit_paddings,
        })
    }
}

#[cfg(feature = "rage")]
impl SyscallInvoker for RopInvoker {
    unsafe fn invoke(&self, ssn: u16, stub: usize, args: &mut [usize; 11]) -> u32 {
        let target_stub = if stub != 0 {
            stub as *mut c_void
        } else {
            self.syscall_stub
        };

        if target_stub.is_null() {
            return 0xC0000001;
        }

        // 1. Tercih: boyutu 0x68 olan meşru unwind epilog gadget'ı ile gerçek stack üzerinde trampoline
        if let Some(gadget) = self.gadgets.iter().find(|g| g.size == 0x68) {
            #[cfg(target_arch = "x86_64")]
            {
                return unsafe {
                    indirect_syscall_trampoline(ssn, target_stub, gadget.addr, args.as_mut_ptr())
                };
            }
        }

        // 2. Fallback: Dolaylı çağrı (indirect_syscall)
        #[cfg(target_arch = "x86_64")]
        unsafe {
            indirect_syscall(ssn, target_stub, args.as_mut_ptr())
        }
        #[cfg(not(target_arch = "x86_64"))]
        0xC0000001
    }

    fn name(&self) -> &'static str {
        "Rage/Trampoline"
    }
}
