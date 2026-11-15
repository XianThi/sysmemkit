mod memory;
pub mod include;
pub mod syscalls;
pub mod utils;

use std::ffi::c_void;

pub use memory::buffer::{read, read_buffer, read_buffers, read_bytes, smart_write, write};
pub use memory::process::{
    create_section, get_all_modules, get_module_base, get_pid_by_hash, hijack_handle, map_view_of_section, openfile,
};
pub use memory::scanner::{find_pattern_in, parse_pattern, pattern_scan, pattern_scan_all_local};
pub use syscalls::invoker::{
    do_syscall, indirect_syscall, indirect_syscall_trampoline, DirectInvoker, IndirectInvoker,
    RandomizerInvoker, SyscallInvoker,
};
#[cfg(feature = "rage")]
pub use syscalls::invoker::RopInvoker;
pub use syscalls::resolver::{
    get_ntdll_base, get_ssn_by_hash, get_syscall_number, print_function_bytes,
    DirectStealthResolver, ExportByteResolver, ExportRvaResolver, HookAwareResolver,
};
pub use syscalls::{Ssn, SsnResolver};

/// SysMemKit çalışma seviyeleri ve gizlilik modları (Faz 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Seviye 1: Standart PEB okuma + ntdll Export tablosundan doğrudan byte taraması (0xB8) + Direct Syscall.
    ///
    /// Hook (`0xE9`) kontrolü yapmaz; eğitim amaçlı saf ve en basit sürümdür.
    Basic,

    /// Seviye 2: Hook farkındalıklı SSN çözümleme (Direct Stealth) + ROP/Indirect Syscall.
    ///
    /// Varsayılan moddur. ntdll içi ROP gadget'ları ve rastgele seçilmiş `syscall` stub'ları kullanır.
    #[default]
    DirectStealth,

    /// Seviye 3: Indirect Syscall (ntdll fonksiyonunun kendi içindeki `syscall; ret` talimatına atlama).
    ///
    /// Faz 3'te tam mimariye kavuşacaktır; şimdilik DirectStealth altyapısını kullanır.
    Indirect,

    /// Seviye 4: Tam Gizlilik - Stack Trampoline + Handle Hijacking.
    ///
    /// Faz 4'te tam mimariye kavuşacaktır; şimdilik DirectStealth altyapısını kullanır.
    Rage,
}

/// SysMemKit ana denetleyici yapısı.
///
/// Seçilen [`Mode`] konfigürasyonuna göre uygun `SsnResolver` ve `SyscallInvoker`
/// bileşenlerini barındırır.
pub struct SysMemKit {
    process_handle: *mut c_void,
    ntdll_base: *mut c_void,
    invoker: Box<dyn SyscallInvoker>,
    resolver: Box<dyn SsnResolver>,
    pid: u32,
    mode: Mode,
}

unsafe impl Send for SysMemKit {}
unsafe impl Sync for SysMemKit {}

impl SysMemKit {
    /// Discord overlay sürecine handle hijack ile bağlanır.
    ///
    /// # Safety
    ///
    /// Çağıranın hedef süreç üzerinde yetkisi olmalıdır. Dönen kit hedef süreç kapanınca
    /// geçersizleşir.
    #[cfg(feature = "discord")]
    pub unsafe fn get_discord() -> Option<Self> {
        let (ntdll_base, ntdll_size) = unsafe { get_ntdll_base() };
        if ntdll_base.is_null() {
            println!("ntdll bulunamadı");
            return None;
        }
        #[cfg(feature = "rage")]
        let invoker: Box<dyn SyscallInvoker> = match unsafe { RopInvoker::new(ntdll_base, ntdll_size) } {
            Some(inv) => Box::new(inv),
            None => Box::new(IndirectInvoker::new(ntdll_base, ntdll_size)),
        };
        #[cfg(not(feature = "rage"))]
        let invoker: Box<dyn SyscallInvoker> =
            Box::new(unsafe { IndirectInvoker::new(ntdll_base, ntdll_size) });

        let resolver = HookAwareResolver::new(ntdll_base);
        let hash = utils::dbj2_hash("discord.exe");

        memory::process::get_discord_overlay_pid(invoker.as_ref(), ntdll_base, hash).and_then(|pid| {
            println!("Discord pid : {:?}", pid);
            memory::process::hijack_handle(invoker.as_ref(), ntdll_base, pid).map(|handle| Self {
                process_handle: handle,
                ntdll_base,
                invoker,
                resolver: Box::new(resolver),
                pid,
                mode: Mode::DirectStealth,
            })
        })
    }

    /// `get_discord` eski adı (geriye dönük uyumluluk).
    ///
    /// # Safety
    ///
    /// `get_discord` ile aynı sözleşme.
    #[cfg(feature = "discord")]
    #[allow(non_snake_case)]
    pub unsafe fn getDiscord() -> Option<Self> {
        unsafe { Self::get_discord() }
    }

    /// Süreç adı veya hash'inden belirtilen mod ile yeni bir kit açar.
    ///
    /// # Safety
    ///
    /// `target_name` geçerli bir süreç adı (veya `hashed` ise sayısal hash) olmalıdır; fonksiyon
    /// handle hijack yapar ve hedef süreçte handle açar.
    pub unsafe fn with_mode(target_name: &str, hashed: bool, mode: Mode) -> Option<Self> {
        let (ntdll_base, ntdll_size) = unsafe { get_ntdll_base() };
        if ntdll_base.is_null() {
            println!("ntdll bulunamadı");
            return None;
        }

        let resolver: Box<dyn SsnResolver> = match mode {
            Mode::Basic => Box::new(ExportByteResolver::new(ntdll_base)),
            Mode::DirectStealth | Mode::Indirect | Mode::Rage => {
                Box::new(DirectStealthResolver::new(ntdll_base))
            }
        };

        let invoker: Box<dyn SyscallInvoker> = match mode {
            Mode::Basic | Mode::DirectStealth => Box::new(DirectInvoker),
            Mode::Indirect => Box::new(unsafe { IndirectInvoker::new(ntdll_base, ntdll_size) }),
            #[cfg(feature = "rage")]
            Mode::Rage => Box::new(unsafe { RopInvoker::new(ntdll_base, ntdll_size)? }),
            #[cfg(not(feature = "rage"))]
            Mode::Rage => Box::new(unsafe { IndirectInvoker::new(ntdll_base, ntdll_size) }),
        };

        let hash: u32 = if hashed {
            target_name.trim().parse::<u32>().ok()?
        } else {
            utils::dbj2_hash(&target_name.to_lowercase())
        };

        unsafe {
            let pid = memory::process::get_pid_by_hash(invoker.as_ref(), ntdll_base, hash)?;
            let handle = memory::process::hijack_handle(invoker.as_ref(), ntdll_base, pid)?;
            Some(Self {
                process_handle: handle,
                ntdll_base,
                invoker,
                resolver,
                pid,
                mode,
            })
        }
    }

    /// Süreç adı veya hash'inden varsayılan `Mode::DirectStealth` ile yeni bir kit açar.
    ///
    /// # Safety
    ///
    /// `target_name` geçerli bir süreç adı (veya `hashed` ise sayısal hash) olmalıdır; fonksiyon
    /// handle hijack yapar ve hedef süreçte handle açar.
    pub unsafe fn new(target_name: &str, hashed: bool) -> Option<Self> {
        unsafe { Self::with_mode(target_name, hashed, Mode::DirectStealth) }
    }

    /// Mevcut bir süreç tanıtıcısı (handle) üzerinden belirtilen mod ile kit açar.
    ///
    /// # Safety
    ///
    /// `process_handle` geçerli bir Windows süreç tanıtıcısı veya sözde tanıtıcı (-1) olmalıdır.
    pub unsafe fn from_handle(process_handle: *mut c_void, pid: u32, mode: Mode) -> Option<Self> {
        let (ntdll_base, ntdll_size) = unsafe { get_ntdll_base() };
        if ntdll_base.is_null() {
            return None;
        }

        let resolver: Box<dyn SsnResolver> = match mode {
            Mode::Basic => Box::new(ExportByteResolver::new(ntdll_base)),
            Mode::DirectStealth | Mode::Indirect | Mode::Rage => {
                Box::new(DirectStealthResolver::new(ntdll_base))
            }
        };

        let invoker: Box<dyn SyscallInvoker> = match mode {
            Mode::Basic | Mode::DirectStealth => Box::new(DirectInvoker),
            Mode::Indirect => Box::new(unsafe { IndirectInvoker::new(ntdll_base, ntdll_size) }),
            #[cfg(feature = "rage")]
            Mode::Rage => Box::new(unsafe { RopInvoker::new(ntdll_base, ntdll_size)? }),
            #[cfg(not(feature = "rage"))]
            Mode::Rage => Box::new(unsafe { IndirectInvoker::new(ntdll_base, ntdll_size) }),
        };

        Some(Self {
            process_handle,
            ntdll_base,
            invoker,
            resolver,
            pid,
            mode,
        })
    }

    /// Hedef süreçten `T` okur.
    ///
    /// # Safety
    ///
    /// `address` hedef süreçte okunabilir olmalı ve `T` POD olmalıdır. Başarısız okumada
    /// sıfırlanmış değer döner.
    pub unsafe fn read<T>(&self, address: usize) -> T {
        unsafe {
            memory::buffer::read(
                self.invoker.as_ref(),
                self.ntdll_base,
                self.process_handle,
                address,
            )
        }
    }

    /// Hedef süreçten ham bayt okur.
    ///
    /// # Safety
    ///
    /// `address..address+size` hedef süreçte okunabilir olmalıdır.
    pub unsafe fn read_buffer(&self, address: usize, size: usize) -> Vec<u8> {
        unsafe {
            memory::buffer::read_buffers(
                self.invoker.as_ref(),
                self.ntdll_base,
                self.process_handle,
                address,
                size,
            )
        }
    }

    /// Hedef sürece `T` yazar.
    ///
    /// # Safety
    ///
    /// `address` hedef süreçte yazılabilir olmalı ve `T` içinde geçersiz işaretçi bulunmamalıdır.
    /// Sayfa koruması geçici olarak değiştirilir.
    pub unsafe fn write<T>(&self, address: usize, value: T) -> bool {
        unsafe {
            memory::buffer::write(
                self.invoker.as_ref(),
                self.ntdll_base,
                self.process_handle,
                address,
                value,
            )
        }
    }

    /// Hedef sürece ham bayt dizisi yazar.
    ///
    /// # Safety
    ///
    /// `address..address+data.len()` hedef süreçte yazılabilir olmalıdır. Sayfa koruması geçici olarak değiştirilir.
    pub unsafe fn write_buffer(&self, address: usize, data: &[u8]) -> bool {
        unsafe {
            memory::buffer::smart_write(
                self.invoker.as_ref(),
                self.ntdll_base,
                self.process_handle,
                address as *mut c_void,
                data,
            )
        }
    }

    /// Hedef süreçte HashMap yapısını pattern ile bulur.
    ///
    /// # Safety
    ///
    /// `module_base`/`module_size` hedef süreçteki gerçek bir modül eşlemesini tanımlamalıdır.
    pub unsafe fn find_hash_map(&self, module_base: usize, module_size: usize) -> Option<usize> {
        unsafe { memory::scanner::find_hash_map_pattern(self.process_handle, module_base, module_size) }
    }

    /// Hedef süreç belleğinde pattern arar.
    ///
    /// # Safety
    ///
    /// `start..start+size` hedef süreçte okunabilir olmalıdır; `pattern` geçersiz hex içerirse
    /// `None` döner.
    pub unsafe fn scan(&self, pattern: &str, start: usize, size: usize) -> Option<usize> {
        unsafe { memory::scanner::pattern_scan(self.process_handle, start, size, pattern) }
    }

    /// Hedef süreçte modül taban adresini döndürür.
    ///
    /// # Safety
    ///
    /// `module_name` hedef süreçte yüklü bir modül adı olmalıdır (uzantı dahil, ör.
    /// `kernel32.dll`).
    pub unsafe fn getmodule(&self, module_name: &str) -> Option<usize> {
        let module_name_hash = utils::dbj2_hash(&module_name.to_lowercase());
        unsafe {
            memory::process::get_module_base(
                self.invoker.as_ref(),
                self.ntdll_base,
                self.process_handle,
                module_name_hash,
            )
        }
    }

    /// Hedef süreçteki tüm yüklü modülleri (ad, taban adresi) liste olarak döndürür.
    ///
    /// # Safety
    ///
    /// Süreç handle'ı geçerli ve okunabilir olmalıdır.
    pub unsafe fn list_modules(&self) -> Vec<(String, usize)> {
        unsafe {
            memory::process::get_all_modules(
                self.invoker.as_ref(),
                self.ntdll_base,
                self.process_handle,
            )
        }
    }

    /// Yerel dosyayı bölüm eşleme için açar.
    ///
    /// # Safety
    ///
    /// `file_path` yerel dosya sisteminde geçerli bir yol olmalıdır; dönen handle çağıran
    /// tarafından kapatılmalıdır.
    pub unsafe fn openfile(&self, file_path: &str) -> Option<*mut c_void> {
        unsafe { memory::process::openfile(self.invoker.as_ref(), self.ntdll_base, file_path) }
    }

    /// Dosya handle'ından `SEC_IMAGE` bölümü oluşturur.
    ///
    /// # Safety
    ///
    /// `file_handle` `openfile` ile alınmış geçerli bir handle olmalıdır.
    pub unsafe fn create_section(&self, file_handle: *mut c_void) -> Option<*mut c_void> {
        unsafe { memory::process::create_section(self.invoker.as_ref(), self.ntdll_base, file_handle) }
    }

    /// Bölümü eşler ve module base döner.
    ///
    /// # Safety
    ///
    /// `section_handle` `create_section` ile alınmış geçerli bir handle olmalıdır.
    pub unsafe fn map_view_of_section(&self, section_handle: *mut c_void) -> Option<*mut c_void> {
        unsafe { memory::process::map_view_of_section(self.invoker.as_ref(), self.ntdll_base, section_handle) }
    }

    /// Hedef süreç handle'ını döner.
    /// Hedef süreç handle'ını döner.
    pub fn handle(&self) -> *mut c_void {
        self.process_handle
    }

    /// ntdll taban adresini döner.
    pub fn ntdll_base(&self) -> *mut c_void {
        self.ntdll_base
    }

    /// İnvoker referansını döner.
    pub fn invoker(&self) -> &dyn SyscallInvoker {
        self.invoker.as_ref()
    }

    /// Resolver referansını döner.
    pub fn resolver(&self) -> &dyn SsnResolver {
        self.resolver.as_ref()
    }

    /// Hedef PID'yi döner.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn get_handle(&self) -> *mut c_void {
        self.process_handle
    }

    /// ntdll taban adresini döner.
    pub fn get_ntdll_base(&self) -> *mut c_void {
        self.ntdll_base
    }

    /// İnvoker referansını döner.
    pub fn get_invoker(&self) -> &dyn SyscallInvoker {
        self.invoker.as_ref()
    }

    /// Resolver referansını döner.
    pub fn get_resolver(&self) -> &dyn SsnResolver {
        self.resolver.as_ref()
    }

    /// Hedef PID'yi döner.
    pub fn get_pid(&self) -> u32 {
        self.pid
    }

    /// Aktif modu döner.
    pub fn mode(&self) -> Mode {
        self.mode
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_defaults() {
        assert_eq!(Mode::default(), Mode::DirectStealth);
    }
}
