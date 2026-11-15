use std::ffi::c_void;
use sysmemkit::{Mode, SysMemKit};

#[derive(Debug, PartialEq, Clone, Copy, Default)]
#[repr(C)]
struct PlayerState {
    health: i32,
    armor: i32,
    pos_x: f32,
    pos_y: f32,
    pos_z: f32,
    flags: u64,
}

#[test]
fn test_all_modes_read_write() {
    let current_process = -1isize as *mut c_void;
    let pid = std::process::id();

    let modes = [
        Mode::Basic,
        Mode::DirectStealth,
        Mode::Indirect,
        Mode::Rage,
    ];

    for &mode in &modes {
        println!("Testing mode: {:?}...", mode);
        let kit = unsafe { SysMemKit::from_handle(current_process, pid, mode) }
            .expect("Failed to create SysMemKit for mode");

        // 1. Primitive Read / Write
        let mut target_val: u32 = 0x12345678;
        let addr = &mut target_val as *mut u32 as usize;

        let read_val: u32 = unsafe { kit.read(addr) };
        assert_eq!(read_val, 0x12345678, "Initial read failed for {:?}", mode);

        let write_ok = unsafe { kit.write(addr, 0xAABBCCDDu32) };
        assert!(write_ok, "Write failed for {:?}", mode);
        assert_eq!(target_val, 0xAABBCCDD, "Written memory verify failed for {:?}", mode);

        let read_back: u32 = unsafe { kit.read(addr) };
        assert_eq!(read_back, 0xAABBCCDD, "Read back failed for {:?}", mode);

        // 2. Buffer Read / Write
        let mut buffer_target: [u8; 16] = [0; 16];
        let buf_addr = buffer_target.as_mut_ptr() as usize;
        let test_payload: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let write_buf_ok = unsafe { kit.write_buffer(buf_addr, &test_payload) };
        assert!(write_buf_ok, "write_buffer failed for {:?}", mode);
        assert_eq!(buffer_target, test_payload, "buffer write verify failed for {:?}", mode);

        let read_buf = unsafe { kit.read_buffer(buf_addr, 16) };
        assert_eq!(read_buf, test_payload, "read_buffer failed for {:?}", mode);

        // 3. Struct Read / Write
        let mut state = PlayerState {
            health: 100,
            armor: 50,
            pos_x: 12.5,
            pos_y: 25.0,
            pos_z: 37.5,
            flags: 0xDEADBEEFCAFEBABE,
        };
        let state_addr = &mut state as *mut PlayerState as usize;

        let read_state: PlayerState = unsafe { kit.read(state_addr) };
        assert_eq!(read_state, state, "Struct read mismatch for {:?}", mode);

        let new_state = PlayerState {
            health: 80,
            armor: 25,
            pos_x: 100.0,
            pos_y: 200.0,
            pos_z: 300.0,
            flags: 0x1122334455667788,
        };
        let write_state_ok = unsafe { kit.write(state_addr, new_state) };
        assert!(write_state_ok, "Struct write failed for {:?}", mode);
        assert_eq!(state, new_state, "Struct target mismatch for {:?}", mode);

        let verify_state: PlayerState = unsafe { kit.read(state_addr) };
        assert_eq!(verify_state, new_state, "Struct read_back mismatch for {:?}", mode);

        println!("Mode {:?} PASSED!", mode);
    }
}
