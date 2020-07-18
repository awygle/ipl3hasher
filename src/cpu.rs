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

use gumdrop::Options;
use rayon::prelude::*;
use std::fs::File;
use std::time::{Duration, Instant};
use std::io::prelude::*;

fn parse_hex(s: &str) -> Result<u16, std::num::ParseIntError> {
    u16::from_str_radix(s, 16)
}

#[derive(Debug, Options)]
struct CSumOptions {
    #[options(free, required, help = "The ROM whose checksum must be matched")]
    golden: String,
    #[options(free, required, help = "The seed value for the hash", parse(try_from_str = "parse_hex"))]
    seed: u16,
    #[options(free, help = "The ROM to be modified")]
    source: String,
    #[options(default = "0", help = "The Y coordinate to start with")]
    init: u32,
}

fn main() {
    let opts = CSumOptions::parse_args_default_or_exit();
    let target_high;
    let target_low;
    if let Ok(mut file) = File::open(opts.golden) {
        let mut rom: [u8; 4096] = [0; 4096];
        if let Ok(_) = file.read_exact(&mut rom) {
            //println!("First byte is {:#X}", rom[0x40]);
            let mut target_csum: ChecksumInfo<BigEndian> = ChecksumInfo::new(opts.seed as u32, rom);

            target_csum.checksum(0, 1008);
            target_csum.finalize_checksum();

            println!("Target checksum: {:#06X} {:08X}", target_csum.high, target_csum.low);
            target_high = target_csum.high;
            target_low = target_csum.low;
        }
        else {
            panic!();
        }
    }
    else {
        panic!();
    }

    if let Ok(mut file) = File::open(opts.source) {
        let mut rom: [u8; 4096] = [0; 4096];
        if let Ok(_) = file.read_exact(&mut rom) {
            let mut pre_csum: ChecksumInfo<BigEndian> = ChecksumInfo::new(opts.seed as u32, rom);

            pre_csum.checksum(0, 1005);

            let unlocked = std::io::stdout();
            let mut stdout = unlocked.lock();
            for y in opts.init..=u32::MAX {
                let mut y_csum = pre_csum.clone();
                y_csum.rom[4088] = (y >> 24) as u8;
                y_csum.rom[4089] = (y >> 16) as u8;
                y_csum.rom[4090] = (y >> 8) as u8;
                y_csum.rom[4091] = (y >> 0) as u8;

                y_csum.checksum(1005, 1006);
                
                stdout.write_fmt(format_args!("executing y == {}\n", y));

                let start = Instant::now();
                let success_val = (0..=u32::MAX).into_par_iter().find_any(|x| {
                    let mut csum = y_csum.clone();
                    csum.rom[4092] = (x >> 24) as u8;
                    csum.rom[4093] = (x >> 16) as u8;
                    csum.rom[4094] = (x >> 8) as u8;
                    csum.rom[4095] = (x >> 0) as u8;
                    csum.checksum(1006, 1008);
                    csum.finalize_checksum();

                    if csum.high == target_high && csum.low == target_low {
                        println!("Result checksum: {:#06X} {:08X}", csum.high, csum.low);
                        println!("Success found with final two words of {:#X}, {:#X}",
                                 y, x);
                        return true;
                    }
                    else {
                        false
                    }
                });

                if success_val.is_some() {
                    return;
                }

                let duration = start.elapsed();
                stdout.write_fmt(format_args!("Inner loop took {:?}\n", duration));
            }

            println!("Exhaustively tested all u64 values and failed! How did you wait this long?");
        }
    }
}