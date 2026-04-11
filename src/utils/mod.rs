pub const fn dbj2_hash(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        hash = (hash << 5).wrapping_add(hash).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Vec3 {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

impl Vec3 {
    pub fn distance(&self, other: &Vec3) -> f32 {
        ((self.x - other.x).powi(2) + (self.y - other.y).powi(2) + (self.z - other.z).powi(2))
            .sqrt()
    }
}
