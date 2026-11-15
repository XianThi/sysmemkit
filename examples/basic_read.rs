use std::process;
use sysmemkit::{Mode, SysMemKit};

fn main() {
    let current_pid = process::id();
    println!("[*] SysMemKit Faz 1 - Basic Read Örneği");
    println!("[*] Geçerli PID: {}", current_pid);

    unsafe {
        // Mode::Basic kullanarak kendi sürecimize bağlanma
        if let Some(kit) = SysMemKit::with_mode(&current_pid.to_string(), true, Mode::Basic) {
            println!("[+] SysMemKit başarıyla başlatıldı (Mod: {:?})", kit.mode());
            println!("[+] ntdll taban adresi: {:?}", kit.ntdll_base());
            println!("[+] Hedef PID: {}", kit.pid());

            // ntdll tabanından ilk 2 baytı oku ('MZ' kontrolü)
            let ntdll_base_addr = kit.ntdll_base() as usize;
            let magic: u16 = kit.read(ntdll_base_addr);
            println!("[+] ntdll DOS Magic: 0x{:04X} (Beklenen: 0x5A4D)", magic);

            if magic == 0x5A4D {
                println!("[+] Bellek okuma başarılı!");
            } else {
                println!("[-] Beklenmeyen DOS Magic değeri!");
            }
        } else {
            println!("[-] SysMemKit başlatılamadı.");
        }
    }
}
