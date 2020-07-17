use std::io::Read;
use std::env;
use byteorder::{ByteOrder, BigEndian, LittleEndian, ReadBytesExt};

#[derive(Clone)]
pub struct ChecksumInfo<E: ByteOrder> {
    pub buffer: [u32; 16],
    pub low: u32,
    pub high: u32,
    pub rom: [u8; 4096],
    endianness: std::marker::PhantomData<E>
}

pub fn checksum_function(a0: u32, a1: u32, a2: u32) -> u32 {
    let a1 = if a1 == 0 { a2 } else { a1 };
    
    let prod = (a0 as u64) * (a1 as u64);
    let hi = (prod >> 32) as u32;
    let lo = prod as u32;
    let diff = hi - lo;
    if diff == 0 {
        a0
    } else {
        diff
    }
}

const MAGIC_NUMBER: u32 = 0x6c07_8965;

impl<E: ByteOrder> ChecksumInfo<E> {
    pub fn rom_word(&self, idx: usize) -> u32 {
        E::read_u32(&self.rom[(idx * 4)..])
    }

    pub fn new(seed: u32, rom: [u8; 4096]) -> ChecksumInfo<E> {
        let init = MAGIC_NUMBER * (seed & 0xFF) + 1;
        //println!("init is {:#X}", init);
        let data = E::read_u32(&rom[0x40..]);
        let init = init ^ data;
        
        ChecksumInfo {
            buffer: [init; 16],
            low: 0,
            high: 0,
            rom,
            endianness: std::marker::PhantomData::<E>,
        }
    }
    
    pub fn calc_checksum(&mut self) {
        self.checksum(0, 1008);
    }
    
    pub fn checksum(&mut self, start: u32, count: u32) {
        let mut data_idx = (start as usize) * 4;
        let mut loop_idx = start;
        let mut data = E::read_u32(&self.rom[(0x40+data_idx)..]);
        
        loop {
            loop_idx += 1;
            //println!("checksum loop iteration {}, data_idx is {}", loop_idx, data_idx);
            //println!("{{");
            for v in self.buffer.iter() {
                //println!("\t{:#X}", v);
            }
            //println!("}}");
            let data_last = data;
            data = E::read_u32(&self.rom[(0x40+data_idx)..]);
            data_idx += 4;
            let data_next = if loop_idx < 1008 { 
                E::read_u32(&self.rom[(0x40+data_idx)..]) 
            } else {
                0
            };
            
            let sum = checksum_function(1007 - loop_idx, data, loop_idx);
            self.buffer[0] += sum;
            
            let sum = checksum_function(self.buffer[1], data, loop_idx);
            self.buffer[1] = sum;
            self.buffer[2] ^= data;
            
            let sum = checksum_function(data + 5, MAGIC_NUMBER, loop_idx);
            self.buffer[3] += sum;
            
            //println!("dataLast: {}, data: {}", data_last, data);
            if (data_last < data) {
                //println!("less than");
                let sum = checksum_function(self.buffer[9], data, loop_idx);
                self.buffer[9] = sum;
            }
            else {
                //println!("greater than");
                self.buffer[9] += data;
            }
            
            let shift = data_last & 0x1f;
            let data_shifted_right = data >> shift;
            let data_shifted_left = data << (32 - shift);
            let tmp = data_shifted_right | data_shifted_left;
            self.buffer[4] += tmp;
            
            let data_shifted_left = data << shift;
            let data_shifted_right = data >> (32 - shift);
            
            let sum = checksum_function(self.buffer[7], data_shifted_left | data_shifted_right, loop_idx);
            self.buffer[7] = sum;
            
            if (data < self.buffer[6]) {
                self.buffer[6] = (self.buffer[3] + self.buffer[6]) ^ (data + loop_idx);
            }
            else {
                self.buffer[6] = (self.buffer[4] + data) ^ self.buffer[6];
            }
            
            let shift = data_last >> 27;
            let data_shifted_right = data >> (32 - shift);
            let data_shifted_left = data << shift;
            let tmp2 = data_shifted_right | data_shifted_left;
            self.buffer[5] += tmp2;
            
            let data_shifted_left = data << (32 - shift);
            let data_shifted_right = data >> shift;
            
            let sum = checksum_function(self.buffer[8], data_shifted_right | data_shifted_left, loop_idx);
            self.buffer[8] = sum;
            
            if loop_idx == 1008 { break; }
            
            let sum = checksum_function(self.buffer[15], tmp2, loop_idx);
            
            let shift = data >> 27;
            let data_shifted_left = data_next << shift;
            let data_shifted_right = data_next >> (32 - shift);
            
            let sum = checksum_function(sum, data_shifted_left | data_shifted_right, loop_idx);
            self.buffer[15] = sum;
            
            let sum = checksum_function(self.buffer[14], tmp, loop_idx);
            
            let shift = data & 0x1f;
            let tmp2 = shift;
            let data_shifted_left = data_next << (32 - shift);
            let data_shifted_right = data_next >> shift;
            
            let sum = checksum_function(sum, data_shifted_right | data_shifted_left, loop_idx);
            self.buffer[14] = sum;
            
            let data_shifted_right = data >> tmp2;
            let data_shifted_left = data << (32 - tmp2);
            let tmp3 = data_shifted_right | data_shifted_left;
            
            let shift = data_next & 0x1f;
            let data_shifted_right = data_next >> shift;
            let data_shifted_left = data_next << (32 - shift);
            
            self.buffer[13] += tmp3 + (data_shifted_right | data_shifted_left);
            
            let sum = checksum_function(self.buffer[10] + data, data_next, loop_idx);
            self.buffer[10] = sum;
            
            let sum = checksum_function(self.buffer[11] ^ data, data_next, loop_idx);
            self.buffer[11] = sum;
            
            self.buffer[12] += self.buffer[8] ^ data;
            
            if loop_idx == count { break; }
        }
    }
    
    pub fn finalize_checksum(&mut self) {
        let mut buf = [self.buffer[0]; 4];
        
        for i in 0..16 {
            let data = self.buffer[i];
            
            let shift = data & 0x1f;
            let data_shifted_left = data << (32 - shift);
            let data_shifted_right = data >> shift;
            let tmp = buf[0] + (data_shifted_right | data_shifted_left);
            buf[0] = tmp;
            
            if data < tmp {
                buf[1] += data;
            } else {
                buf[1] = checksum_function(buf[1], data, i as u32);
            }
            
            let tmp = (data & 0x02) >> 1;
            let tmp2 = data & 0x01;
            
            if tmp == tmp2 {
                buf[2] += data;
            } else {
                buf[2] = checksum_function(buf[2], data, i as u32);
            }
            
            if tmp2 == 1 {
                buf[3] ^= data;
            } else {
                buf[3] = checksum_function(buf[3], data, i as u32);
            }
        }
        
        let sum = checksum_function(buf[0], buf[1], 16);
        let tmp = buf[3] ^ buf[2];
        
        let checksum = (sum as u64) << 32;
        let checksum = checksum | (tmp as u64);
        let checksum = checksum & 0xffffffffffffu64;
        
        self.low = checksum as u32;
        self.high = (checksum >> 32) as u32;
    }
}
