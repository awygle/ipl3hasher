use emu_core::prelude::*;
use emu_glsl::*;
//use zerocopy::*;
use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use rand::Rng;
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;

use std::time::{Duration, Instant};

mod cpu;
use cpu::*;

use gumdrop::Options;

fn parse_hex(s: &str) -> Result<u16, std::num::ParseIntError> {
    u16::from_str_radix(s, 16)
}

fn parse_hex_u32(s: &str) -> Result<u32, std::num::ParseIntError> {
    u32::from_str_radix(s, 16)
}

#[derive(Debug, Options)]
struct CSumOptions {
    #[options(free, required, help = "The ROM whose checksum must be matched")]
    golden: String,
    #[options(
        free,
        required,
        help = "The seed value for the hash",
        parse(try_from_str = "parse_hex")
    )]
    seed: u16,
    #[options(free, help = "The ROM to be modified")]
    source: String,
    #[options(
        default = "400",
        help = "The number of threads to use",
        parse(try_from_str = "parse_hex_u32")
    )]
    threads: u32,
    #[options(
        default = "20000",
        help = "The number of groups to use",
        parse(try_from_str = "parse_hex_u32")
    )]
    groups: u32,
    #[options(default = "0", help = "The Y coordinate to start with")]
    init: u32,
    #[options(
        short = "v",
        default = "false",
        help = "Print each range of hashes as they're sent to the GPU"
    )]
    verbose: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = CSumOptions::parse_args_default_or_exit();
    let target_high;
    let target_low;
    if let Ok(mut file) = File::open(opts.golden) {
        let mut rom: [u8; 4096] = [0; 4096];
        if let Ok(_) = file.read_exact(&mut rom) {
            let mut target_csum: ChecksumInfo<BigEndian> = ChecksumInfo::new(opts.seed as u32, rom);
            target_csum.checksum(0, 1008);
            target_csum.finalize_checksum();
            target_high = target_csum.high;
            target_low = target_csum.low;
        } else {
            panic!();
        }
    } else {
        panic!();
    }

    println!("Target checksum: {:#06X} {:08X}", target_high, target_low);

    let mut pre_csum: ChecksumInfo<BigEndian>;

    if let Ok(mut file) = File::open(opts.source) {
        let mut rom: [u8; 4096] = [0; 4096];
        if let Ok(_) = file.read_exact(&mut rom) {
            pre_csum = ChecksumInfo::new(opts.seed as u32, rom);
            pre_csum.checksum(0, 1005);
        } else {
            panic!();
        }
    } else {
        panic!();
    }

    // ensure that a device pool has been initialized
    // this should be called before every time when you assume you have devices to use
    // that goes for both library users and application users
    futures::executor::block_on(assert_device_pool_initialized());

    println!("{:?}", take()?.lock().unwrap().info.as_ref().unwrap());

    // create some data on GPU
    // even mutate it once loaded to GPU
    //let mut state: DeviceBox<[u32]> = vec![0; 16].as_device_boxed_mut()?;
    let mut res: DeviceBox<[u32]> = vec![0u32, 0u32].as_device_boxed_mut()?;
    let mut x_off_src = 0u64;
    let mut y_off_src = opts.init as u64;
    let mut x_off: DeviceBox<u32> = 0u32.into_device_boxed_mut()?;
    let mut y_off: DeviceBox<u32> = 0u32.into_device_boxed_mut()?;
    let mut finished: DeviceBox<[u32]> = vec![0u32].as_device_boxed_mut()?;

    // compile GslKernel to SPIR-V
    // then, we can either inspect the SPIR-V or finish the compilation by generating a DeviceFnMut
    // then, run the DeviceFnMut
    let kernel = GlslKernel::new()
    .spawn(opts.threads)
    .param::<[u32], _>("uint[16] state_in")
    .param_mut::<u32, _>("uint x_offset")
    .param_mut::<u32, _>("uint y_offset")
    .param_mut::<[u32], _>("uint[1] finished")
    .param_mut::<[u32], _>("uint[2] result")
    .with_const("uint magic", "0x95DACFDC")
    .with_const("uint target_hi", format!("{}", target_high))
    .with_const("uint target_lo", format!("{}", target_low))
    .with_const("uint seed", format!("{}", opts.seed as u32))
.with_helper_code(r#"
uint csum(uint op1, uint op2, uint op3) {
    uint hi;
    uint lo;
    if (op2 == 0) {
        op2 = op3;
    }

    umulExtended(op1, op2, hi, lo);

    if (hi - lo == 0) {
        return lo;
    }

    return hi - lo;
}

uint[16] round(uint[16] state, uint data_last, uint data, uint data_next, uint loop_count) {
    state[0] += csum(uint(0x3EF - loop_count), data, loop_count);
    state[1] = csum(state[1], data, loop_count);
    state[2] ^= data;
    state[3] += csum(data + 5, 0x6c078965, loop_count);

    if (data_last < data) {
        state[9] = csum(state[9], data, loop_count);
    }
    else {
        state[9] += data;
    }

    state[4] += ((data << (0x20 - (data_last & 0x1f))) | (data >> (data_last & 0x1f)));
    state[7] = csum(state[7], ((data >> (0x20 - (data_last & 0x1f))) | (data << (data_last & 0x1f))), loop_count);

    if (data < state[6]) {
        state[6] = (data + loop_count) ^ (state[3] + state[6]);
    }
    else {
        state[6] = (state[4] + data) ^ state[6];
    }

    state[5] += (data >> (0x20 - (data_last >> 27))) | (data << (data_last >> 27));
    state[8] = csum(state[8], (data << (0x20 - (data_last >> 27))) | (data >> (data_last >> 27)), loop_count);

    if (loop_count == 0x3F0) return state;

    uint tmp1 = csum(state[15], (data >> (0x20 - (data_last >> 27))) | (data << (data_last >> 27)), loop_count);
    state[15] = csum(tmp1, (data_next << (data >> 27)) | (data_next >> (0x20 - (data >> 27))), loop_count);

    uint tmp2 = ((data << (0x20 - (data_last & 0x1f))) | (data >> (data_last & 0x1f)));
    uint tmp3 = csum(state[14], tmp2, loop_count);
    uint tmp4 = csum(tmp3, (data_next >> (data & 0x1f)) | (data_next << (0x20 - (data & 0x1f))), loop_count);

    state[14] = tmp4;
    state[13] += ((data >> (data & 0x1f)) | (data << (0x20 - (data & 0x1f)))) + ((data_next >> (data_next & 0x1f)) | (data_next << (0x20 - (data_next & 0x1f))));
    state[10] = csum(state[10] + data, data_next, loop_count);
    state[11] = csum(state[11] ^ data, data_next, loop_count);
    state[12] += (state[8] ^ data);

    return state;
}

uint[2] finalize(uint[16] state) {
    uint buf[4];

    for (int i = 0; i < 4; i++) {
        buf[i] = state[0];
    }

    for (uint i = 0; i < 16; i++) {
        uint data = state[i];
        uint shift = data & 0x1f;
        uint data_shifted_left = data << (32 - shift);
        uint data_shifted_right = data >> shift;
        uint tmp = buf[0] + (data_shifted_right | data_shifted_left);
        buf[0] = tmp;

        if (data < tmp) {
            buf[1] += data;
        }
        else {
            buf[1] = csum(buf[1], data, i);
        }

        tmp = (data & 0x02) >> 1;
        uint tmp2 = data & 0x01;

        if (tmp == tmp2) {
            buf[2] += data;
        }
        else {
            buf[2] = csum(buf[2], data, i);
        }

        if (tmp2 == 1) {
            buf[3] ^= data;
        }
        else {
            buf[3] = csum(buf[3], data, i);
        }
    }

    uint res[2];
    res[1] = csum(buf[0], buf[1], 16) & 0xFFFF;
    res[0] = buf[3] ^ buf[2];
    return res;
}

uint[2] crunch(uint[16] state_in, uint hi, uint lo) {
    uint state[16];
    for (int i = 0; i < 16; i++) {
        state[i] = state_in[i];
    }

    uint data_last = 0;
    uint data = hi;
    uint data_next = lo;
    uint loop_count = 1007;

    state = round(state, data_last, data, data_next, loop_count);

    data_last = data;
    data = data_next;
    data_next = 0;
    loop_count = 1008;

    state = round(state, data_last, data, data_next, loop_count);

    return finalize(state);
}
"#)
.with_kernel_code(
r#"
    uint y = y_offset;
    uint x = x_offset + gl_GlobalInvocationID.x;
    uint local_result[2] = crunch(state_in, y, x);
    if (local_result[1] == target_hi && local_result[0] == target_lo) {
        if (atomicOr(finished[0], 1) == 0) {
            result[0] = x;
            result[1] = y;
        }
    }
"#,
);
    let c = compile::<GlslKernel, GlslKernelCompile, Vec<u32>, GlobalCache>(kernel)?.finish()?;
    //return Ok(());
    let mut finished_src;
    let unlocked = std::io::stdout();
    let mut stdout = unlocked.lock();
    loop {
        x_off_src = 0;
        x_off.set(x_off_src as u32)?;
        let mut y_csum = pre_csum.clone();
        y_csum.rom[4088] = (y_off_src >> 24) as u8;
        y_csum.rom[4089] = (y_off_src >> 16) as u8;
        y_csum.rom[4090] = (y_off_src >> 8) as u8;
        y_csum.rom[4091] = (y_off_src >> 0) as u8;
        y_csum.checksum(1005, 1006);
        let state_vec: Vec<u32> = y_csum.buffer.iter().cloned().collect();
        let state_in: DeviceBox<[u32]> = state_vec.as_device_boxed()?;
        let start = Instant::now();
        loop {
            let bump = (opts.threads as u64) * (opts.groups as u64);
            if opts.verbose {
                stdout.write_fmt(format_args!(
                    "should calc from ({}, {}) to ({}, {}) in {} threads on {} workgroups\n",
                    x_off_src,
                    y_off_src,
                    x_off_src + bump,
                    y_off_src,
                    opts.threads,
                    opts.groups
                ))?;
            }
            unsafe {
                spawn(opts.groups).launch(call!(
                    c.clone(),
                    &state_in,
                    &mut x_off,
                    &mut y_off,
                    &mut finished,
                    &mut res
                ))?;
            }
            finished_src = futures::executor::block_on(finished.get())?[0] == 1;
            if finished_src {
                break;
            }

            x_off_src += bump;

            if x_off_src >= std::u32::MAX as u64 {
                break;
            }

            x_off.set(x_off_src as u32)?;
        }
        let duration = start.elapsed();
        write!(stdout, "Inner loop Y=={} took {:?}\n", y_off_src, duration)?;
        stdout.flush()?;
        //return Ok(());

        if finished_src {
            break;
        }

        y_off_src += 1;

        if y_off_src >= std::u32::MAX as u64 {
            break;
        }

        y_off.set(y_off_src as u32)?;
    }

    // download from GPU and print out
    if finished_src {
        println!("{:#X?}", futures::executor::block_on(res.get())?);
    } else {
        println!("sorry, no dice");
    }
    Ok(())
}
