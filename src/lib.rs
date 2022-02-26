#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![cfg_attr(feature = "nightly", feature(core_intrinsics))]
#![cfg_attr(feature = "nightly", feature(bench_black_box))]
#![cfg_attr(feature = "nightly", feature(once_cell))]

#[cfg(test)]
mod test_data;
#[cfg(test)]
mod tests;

mod pointers;

use pointers::{Ptr, PtrMut};

use cfg_if::cfg_if;
use std::mem::{size_of, size_of_val};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Hash128 {
    pub low64: u64,  // value & 0xFFFFFFFFFFFFFFFF
    pub high64: u64, // value >> 64
}

cfg_if! {
    if #[cfg(target_feature = "avx2")] {
        #[repr(align(32))]
        struct Acc([u64; 8]);
    } else if #[cfg(target_feature = "sse2")] {
        #[repr(align(16))]
        struct Acc([u64; 8]);
    } else {
        struct Acc([u64; 8]);
    }
}

#[cfg(not(target_feature = "sse2"))]
const XXH_ACC_ALIGN: usize = 16;
const XXH3_MIDSIZE_MAX: u64 = 240;
const XXH3_INTERNALBUFFER_SIZE: usize = 256;
const XXH3_SECRET_DEFAULT_SIZE: usize = 192;
const XXH_SECRET_MERGEACCS_START: usize = 11;
const XXH_SECRET_LASTACC_START: usize = 7;
const XXH3_SECRET_SIZE_MIN: usize = 136;
const XXH3_MIDSIZE_LASTOFFSET: usize = 17;
const XXH3_MIDSIZE_STARTOFFSET: usize = 3;

const XXH_PRIME64_1: u64 = 0x9E3779B185EBCA87;
const XXH_PRIME64_2: u64 = 0xC2B2AE3D27D4EB4F;
const XXH_PRIME64_3: u64 = 0x165667B19E3779F9;
const XXH_PRIME64_4: u64 = 0x85EBCA77C2B2AE63;
const XXH_PRIME64_5: u64 = 0x27D4EB2F165667C5;

const XXH3_INIT_ACC: Acc = Acc([
    XXH_PRIME32_3 as u64,
    XXH_PRIME64_1,
    XXH_PRIME64_2,
    XXH_PRIME64_3,
    XXH_PRIME64_4,
    XXH_PRIME32_2 as u64,
    XXH_PRIME64_5,
    XXH_PRIME32_1 as u64,
]);

#[cfg(feature = "support_seed")]
const XXH_SECRET_DEFAULT_SIZE: usize = 192; // minimum XXH3_SECRET_SIZE_MIN

const XXH3_kSecret: Secret = Secret([
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,
    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
]);

#[repr(align(64))]
struct Buffer([u8; XXH3_INTERNALBUFFER_SIZE]);

impl Buffer {
    #[inline]
    fn as_ptr(&self) -> Ptr<u8> {
        Ptr::from(&self.0[..])
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> PtrMut<u8> {
        PtrMut::from(&mut self.0[..])
    }
}

#[repr(align(64))]
struct Secret([u8; XXH3_SECRET_DEFAULT_SIZE]);

impl Secret {
    #[cfg(feature = "support_seed")]
    #[inline]
    fn as_ptr(&self) -> Ptr<u8> {
        Ptr::from(&self.0[..])
    }

    #[cfg(feature = "support_seed")]
    #[inline]
    fn as_mut_ptr(&mut self) -> PtrMut<u8> {
        PtrMut::from(&mut self.0[..])
    }
}

pub struct Xxh3Hasher {
    acc: Acc,
    #[cfg(feature = "support_seed")]
    custom_secret: Secret,
    buffer: Buffer,
    buffered_size: usize,
    num_stripes_so_far: usize,
    total_len: u64,
    num_stripes_per_block: usize,
    secret_limit: usize,
    seed: u64,
}

impl std::fmt::Debug for Xxh3Hasher {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn write_bytes<T>(
            f: &mut std::fmt::Formatter<'_>,
            tag: &str,
            slice: &[T],
        ) -> std::fmt::Result {
            let r = slice.as_ptr_range();
            let mut p = r.start as *const u8;
            let end = r.end as *const u8;

            write!(f, "{}", tag)?;

            let mut i = 0;

            unsafe {
                while p != end {
                    if i % 8 == 7 {
                        write!(f, "_")?;
                    }

                    write!(f, "{:02x}", *p)?;
                    p = p.offset(1);
                    i += 1;
                }
            }

            writeln!(f)
        }

        writeln!(f, "XXH3State {{")?;
        write_bytes(f, "  acc          = ", &self.acc.0[..])?;
        write_bytes(f, "  buffer       = ", &self.buffer.0[..])?;
        #[cfg(feature = "support_seed")]
        write_bytes(f, "  custom_secret = ", &self.custom_secret.0[..])?;

        writeln!(f, "  num_stripes_so_far = {}", self.num_stripes_so_far)?;
        writeln!(f, "  total_len = {}", self.total_len)?;
        writeln!(
            f,
            "  num_stripes_per_block = {}",
            self.num_stripes_per_block
        )?;
        writeln!(f, "  secret_limit = {}", self.secret_limit)?;
        writeln!(f, "  seed         = {}", self.seed)?;
        writeln!(f, "  buffered_size = {}", self.buffered_size)?;
        writeln!(f, "}}")?;

        Ok(())
    }
}

impl Default for Xxh3Hasher {
    #[inline]
    fn default() -> Self {
        let secret = &XXH3_kSecret.0[..];
        let secret_limit = secret.len() - XXH_STRIPE_LEN;
        let num_stripes_per_block = secret_limit / XXH_SECRET_CONSUME_RATE;

        Self {
            acc: XXH3_INIT_ACC,
            #[cfg(feature = "support_seed")]
            custom_secret: unsafe {
                if cfg!(debug_assertions) {
                    Secret([0xCC; XXH3_SECRET_DEFAULT_SIZE])
                } else {
                    std::mem::MaybeUninit::uninit().assume_init()
                }
            },
            buffer: unsafe {
                if cfg!(debug_assertions) {
                    Buffer([0xCC; XXH3_INTERNALBUFFER_SIZE])
                } else {
                    std::mem::MaybeUninit::uninit().assume_init()
                }
            },
            buffered_size: 0,
            num_stripes_so_far: 0,
            total_len: 0,
            num_stripes_per_block,
            secret_limit,
            seed: 0,
        }
    }
}

impl Xxh3Hasher {
    #[inline]
    fn secret(&self) -> &[u8] {
        #[cfg(feature = "support_seed")]
        {
            if self.seed == 0 {
                &XXH3_kSecret.0[..]
            } else {
                &self.custom_secret.0[..]
            }
        }

        #[cfg(not(feature = "support_seed"))]
        {
            &XXH3_kSecret.0[..]
        }
    }
}

cfg_if! {
    if #[cfg(target_feature = "avx2")] {
        const XXH3_accumulate_512: XXH3_f_accumulate_512 = XXH3_accumulate_512_avx2;
        const XXH3_scrambleAcc: XXH3_f_scrambleAcc = XXH3_scrambleAcc_avx2;

        #[cfg(feature = "support_seed")]
        const XXH3_initCustom_secret: XXH3_f_initCustom_secret = XXH3_initCustom_secret_sse2;
    } else if #[cfg(target_feature = "sse2")] {
        const XXH3_accumulate_512: XXH3_f_accumulate_512 = XXH3_accumulate_512_sse2;
        const XXH3_scrambleAcc: XXH3_f_scrambleAcc = XXH3_scrambleAcc_sse2;

        #[cfg(feature = "support_seed")]
        const XXH3_initCustom_secret: XXH3_f_initCustom_secret = XXH3_initCustom_secret_sse2;
    } else {
        const XXH3_accumulate_512: XXH3_f_accumulate_512 = XXH3_accumulate_512_scalar;
        const XXH3_scrambleAcc: XXH3_f_scrambleAcc = XXH3_scrambleAcc_scalar;

        #[cfg(feature = "support_seed")]
        const XXH3_initCustom_secret: XXH3_f_initCustom_secret = XXH3_initCustom_secret_scalar;
    }
}

#[inline]
pub fn XXH3_128bits(input: &[u8]) -> Hash128 {
    XXH3_128bits_internal(input, 0, &XXH3_kSecret.0[..], XXH3_hashLong_128b_default)
}

// Public interface
impl Xxh3Hasher {
    // It's important that the fast path, where we just copy things into the state's buffer gets
    // inlined. It greatly helps performance if the length of the slice is known at compile-time,
    // so we don't spend a lot of time calling memcpy() for small slices.
    #[inline]
    pub fn update(&mut self, input: &[u8]) {
        let input_len = input.len();
        self.total_len += input_len as u64;
        debug_assert!(self.buffered_size <= XXH3_INTERNALBUFFER_SIZE);

        // small input : just fill in tmp buffer
        if self.buffered_size + input_len <= XXH3_INTERNALBUFFER_SIZE {
            let input: Ptr<u8> = input[..].into();

            checked_memcpy(
                self.buffer.as_mut_ptr().offset(self.buffered_size),
                input,
                input_len,
            );
            self.buffered_size += input_len;

            return;
        }

        self.update_internal(&input, XXH3_accumulate_512, XXH3_scrambleAcc);
    }

    // It's important that the fast path, where we just copy things into the state's buffer gets
    // inlined. It greatly helps performance if the length of the slice is known at compile-time,
    // so we don't spend a lot of time calling memcpy() for small slices. This version of update()
    // guarantees this via const generics.
    #[inline]
    pub fn update_fixed_size<const INPUT_SIZE: usize>(&mut self, input: &[u8; INPUT_SIZE]) {
        self.total_len += INPUT_SIZE as u64;
        debug_assert!(self.buffered_size <= XXH3_INTERNALBUFFER_SIZE);

        // small input : just fill in tmp buffer
        if self.buffered_size + INPUT_SIZE <= XXH3_INTERNALBUFFER_SIZE {
            let input: Ptr<u8> = input[..].into();

            checked_memcpy(
                self.buffer.as_mut_ptr().offset(self.buffered_size),
                input,
                INPUT_SIZE,
            );
            self.buffered_size += INPUT_SIZE;

            return;
        }

        self.update_internal(&input[..], XXH3_accumulate_512, XXH3_scrambleAcc);
    }

    #[inline]
    pub fn digest128(mut self) -> Hash128 {
        let secret = self.secret();

        if self.total_len > XXH3_MIDSIZE_MAX {
            let secret: Ptr<u8> = secret.into();

            assert!(size_of::<Acc>() == XXH_ACC_NB * size_of::<u64>());

            self.XXH3_digest_long(secret);

            debug_assert!(
                self.secret_limit + XXH_STRIPE_LEN >= size_of::<Acc>() + XXH_SECRET_MERGEACCS_START
            );

            return Hash128 {
                low64: XXH3_mergeAccs(
                    &mut self.acc,
                    secret.offset(XXH_SECRET_MERGEACCS_START),
                    self.total_len.wrapping_mul(XXH_PRIME64_1),
                ),
                high64: XXH3_mergeAccs(
                    &mut self.acc,
                    secret.offset(
                        self.secret_limit + XXH_STRIPE_LEN
                            - size_of::<Acc>()
                            - XXH_SECRET_MERGEACCS_START,
                    ),
                    !(self.total_len.wrapping_mul(XXH_PRIME64_2)),
                ),
            };
        }
        /* len <= XXH3_MIDSIZE_MAX : short code */

        // Seeds not supported
        #[cfg(feature = "support_seed")]
        if self.seed != 0 {
            return XXH3_128bits_withSeed(&self.buffer.0[..self.total_len as usize], self.seed);
        }

        return XXH3_128bits_withSecret(
            &self.buffer.0[..self.total_len as usize],
            &secret[..self.secret_limit + XXH_STRIPE_LEN],
        );
    }

    #[inline]
    pub fn reset(&mut self) {
        self.reset_internal(0, Some(&XXH3_kSecret.0[..]));
    }

    #[cfg(feature = "support_seed")]
    #[inline]
    pub fn reset_with_seed(&mut self, seed: u64) {
        if seed == 0 {
            return self.reset();
        }

        if seed != self.seed {
            XXH3_initCustom_secret(&mut self.custom_secret, seed);
        }

        self.reset_internal(seed, None);
    }
}

// Internals
impl Xxh3Hasher {
    #[inline(never)]
    fn update_internal(
        &mut self,
        input: &[u8],
        f_acc512: XXH3_f_accumulate_512,
        f_scramble: XXH3_f_scrambleAcc,
    ) {
        let input_len = input.len();
        let mut input: Ptr<u8> = input.into();

        debug_assert!(self.buffered_size + input_len > XXH3_INTERNALBUFFER_SIZE);

        let bEnd = input.offset(input_len);
        let secret: Ptr<u8> = self.secret().into();

        debug_assert!(self.buffered_size <= XXH3_INTERNALBUFFER_SIZE);

        // total input is now > XXH3_INTERNALBUFFER_SIZE
        const XXH3_INTERNALBUFFER_STRIPES: usize = XXH3_INTERNALBUFFER_SIZE / XXH_STRIPE_LEN;
        assert!(XXH3_INTERNALBUFFER_SIZE % XXH_STRIPE_LEN == 0); /* clean multiple */

        // Internal buffer is partially filled (always, except at beginning)
        // Complete it, then consume it.
        if self.buffered_size > 0 {
            let loadSize = XXH3_INTERNALBUFFER_SIZE - self.buffered_size;
            checked_memcpy(
                self.buffer.as_mut_ptr().offset(self.buffered_size),
                input,
                loadSize,
            );
            input = input.offset(loadSize);

            XXH3_consumeStripes(
                &mut self.acc,
                &mut self.num_stripes_so_far,
                self.num_stripes_per_block,
                self.buffer.as_ptr(),
                XXH3_INTERNALBUFFER_STRIPES,
                secret,
                self.secret_limit,
                f_acc512,
                f_scramble,
            );
            self.buffered_size = 0;
        }
        debug_assert!(input.addr() < bEnd.addr());

        // large input to consume : ingest per full block
        if bEnd.distance(input) > self.num_stripes_per_block * XXH_STRIPE_LEN {
            let mut num_stripes = (bEnd.distance(input) - 1) / XXH_STRIPE_LEN;
            debug_assert!(self.num_stripes_per_block >= self.num_stripes_so_far);

            // join to current block's end
            {
                let num_stripesToEnd = self.num_stripes_per_block - self.num_stripes_so_far;
                debug_assert!(num_stripesToEnd <= num_stripes);
                XXH3_accumulate(
                    &mut self.acc,
                    input,
                    secret.offset(self.num_stripes_so_far * XXH_SECRET_CONSUME_RATE),
                    num_stripesToEnd,
                    f_acc512,
                );
                f_scramble(&mut self.acc, secret.offset(self.secret_limit));
                self.num_stripes_so_far = 0;
                input = input.offset(num_stripesToEnd * XXH_STRIPE_LEN);
                num_stripes -= num_stripesToEnd;
            }

            // consume per entire blocks
            while num_stripes >= self.num_stripes_per_block {
                XXH3_accumulate(
                    &mut self.acc,
                    input,
                    secret,
                    self.num_stripes_per_block,
                    f_acc512,
                );
                f_scramble(&mut self.acc, secret.offset(self.secret_limit));
                input = input.offset(self.num_stripes_per_block * XXH_STRIPE_LEN);
                num_stripes -= self.num_stripes_per_block;
            }

            // consume last partial block
            XXH3_accumulate(&mut self.acc, input, secret, num_stripes, f_acc512);
            input = input.offset(num_stripes * XXH_STRIPE_LEN);
            debug_assert!(input.addr() < bEnd.addr()); /* at least some bytes left */
            self.num_stripes_so_far = num_stripes;

            // buffer predecessor of last partial stripe
            checked_memcpy(
                self.buffer
                    .as_mut_ptr()
                    .offset(size_of::<Buffer>() - XXH_STRIPE_LEN),
                input.negative_offset(XXH_STRIPE_LEN),
                XXH_STRIPE_LEN,
            );

            debug_assert!(bEnd.distance(input) <= XXH_STRIPE_LEN);
        } else {
            // content to consume <= block size
            // Consume input by a multiple of internal buffer size */
            if bEnd.distance(input) > XXH3_INTERNALBUFFER_SIZE {
                let limit = bEnd.addr() - XXH3_INTERNALBUFFER_SIZE;
                loop {
                    XXH3_consumeStripes(
                        &mut self.acc,
                        &mut self.num_stripes_so_far,
                        self.num_stripes_per_block,
                        input,
                        XXH3_INTERNALBUFFER_STRIPES,
                        secret,
                        self.secret_limit,
                        f_acc512,
                        f_scramble,
                    );
                    input = input.offset(XXH3_INTERNALBUFFER_SIZE);

                    if !(input.addr() < limit) {
                        break;
                    }
                }

                // buffer predecessor of last partial stripe
                checked_memcpy(
                    self.buffer
                        .as_mut_ptr()
                        .offset(size_of::<Buffer>() - XXH_STRIPE_LEN),
                    input.negative_offset(XXH_STRIPE_LEN),
                    XXH_STRIPE_LEN,
                );
            }
        }

        // Some remaining input (always) : buffer it
        debug_assert!(input.addr() < bEnd.addr());
        debug_assert!(bEnd.distance(input) <= XXH3_INTERNALBUFFER_SIZE);
        debug_assert!(self.buffered_size == 0);
        checked_memcpy(self.buffer.as_mut_ptr(), input, bEnd.distance(input));
        self.buffered_size = bEnd.distance(input);
    }

    #[inline]
    fn reset_internal(&mut self, seed: u64, secret: Option<&'static [u8]>) {
        #[cfg(debug_assertions)]
        {
            self.buffer.0 = [0xCC; XXH3_INTERNALBUFFER_SIZE];
        }

        self.buffered_size = 0;
        self.num_stripes_so_far = 0;
        self.total_len = 0;

        self.acc = XXH3_INIT_ACC;

        self.seed = seed;

        let secretSize = if let Some(secret) = secret {
            secret.len()
        } else {
            #[cfg(feature = "support_seed")]
            debug_assert_eq!(size_of_val(&self.custom_secret), XXH3_SECRET_DEFAULT_SIZE);
            XXH3_SECRET_DEFAULT_SIZE
        };

        debug_assert!(
            secret.map(|x| x.len()).unwrap_or(XXH3_SECRET_DEFAULT_SIZE) >= XXH3_SECRET_SIZE_MIN
        );
        self.secret_limit = secretSize - XXH_STRIPE_LEN;
        self.num_stripes_per_block = self.secret_limit / XXH_SECRET_CONSUME_RATE;
    }

    #[inline]
    fn XXH3_digest_long(&mut self, secret: Ptr<u8>) {
        if self.buffered_size >= XXH_STRIPE_LEN {
            let num_stripes = (self.buffered_size - 1) / XXH_STRIPE_LEN;
            let mut num_stripes_so_far = self.num_stripes_so_far;
            XXH3_consumeStripes(
                &mut self.acc,
                &mut num_stripes_so_far,
                self.num_stripes_per_block,
                self.buffer.as_ptr(),
                num_stripes,
                secret,
                self.secret_limit,
                XXH3_accumulate_512,
                XXH3_scrambleAcc,
            );
            /* last stripe */
            XXH3_accumulate_512(
                &mut self.acc,
                self.buffer
                    .as_ptr()
                    .offset(self.buffered_size - XXH_STRIPE_LEN),
                secret.offset(self.secret_limit - XXH_SECRET_LASTACC_START),
            );
        } else {
            /* buffered_size < XXH_STRIPE_LEN */
            let mut lastStripe = [0u8; XXH_STRIPE_LEN];
            let lastStripe: PtrMut<u8> = (&mut lastStripe[..]).into();
            let catchupSize = XXH_STRIPE_LEN - self.buffered_size;
            debug_assert!(self.buffered_size > 0); /* there is always some input buffered */
            checked_memcpy(
                lastStripe,
                self.buffer
                    .as_ptr()
                    .offset(size_of::<Buffer>() - catchupSize),
                catchupSize,
            );

            checked_memcpy(
                lastStripe.offset(catchupSize),
                self.buffer.as_ptr(),
                self.buffered_size,
            );
            XXH3_accumulate_512(
                &mut self.acc,
                lastStripe.to_const_ptr(),
                secret.offset(self.secret_limit - XXH_SECRET_LASTACC_START),
            );
        }
    }
}

#[inline(never)]
fn XXH3_hashLong_128b_default(input: &[u8], _seed: u64, _secret: &[u8]) -> Hash128 {
    return XXH3_hashLong_128b_internal(
        input,
        &XXH3_kSecret.0[..],
        XXH3_accumulate_512,
        XXH3_scrambleAcc,
    );
}

#[cfg(feature = "support_seed")]
pub fn XXH3_128bits_withSeed(input: &[u8], seed: u64) -> Hash128 {
    XXH3_128bits_internal(
        input,
        seed,
        &XXH3_kSecret.0[..],
        XXH3_hashLong_128b_withSeed,
    )
}

#[cfg(feature = "support_seed")]
#[inline(never)]
fn XXH3_hashLong_128b_withSeed(input: &[u8], seed: u64, _secret: &[u8]) -> Hash128 {
    return XXH3_hashLong_128b_withSeed_internal(
        input,
        seed,
        XXH3_accumulate_512,
        XXH3_scrambleAcc,
        XXH3_initCustom_secret,
    );
}

#[cfg(feature = "support_seed")]
#[inline]
fn XXH3_hashLong_128b_withSeed_internal(
    input: &[u8],
    seed: u64,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc,
    f_initSec: XXH3_f_initCustom_secret,
) -> Hash128 {
    if seed == 0 {
        return XXH3_hashLong_128b_internal(input, &XXH3_kSecret.0[..], f_acc512, f_scramble);
    }

    let mut secret = Secret([0u8; XXH_SECRET_DEFAULT_SIZE]);
    f_initSec(&mut secret, seed);
    return XXH3_hashLong_128b_internal(input, &secret.0[..], f_acc512, f_scramble);
}

type XXH3_f_accumulate_512 = fn(&mut Acc, Ptr<u8>, Ptr<u8>);
type XXH3_f_scrambleAcc = fn(&mut Acc, Ptr<u8>);
type XXH3_hashLong128_f = fn(&[u8], u64, &[u8]) -> Hash128;

#[cfg(feature = "support_seed")]
type XXH3_f_initCustom_secret = fn(&mut Secret, u64);

const XXH_STRIPE_LEN: usize = 64;
const XXH_SECRET_CONSUME_RATE: usize = 8; /* nb of secret bytes consumed at each accumulation */
const XXH_ACC_NB: usize = XXH_STRIPE_LEN / size_of::<u64>();

#[inline]
fn checked_memcpy(dst: PtrMut<u8>, src: Ptr<u8>, byte_count: usize) {
    #[cfg(debug_assertions)]
    src.assert_contains_next_n_bytes(byte_count);

    #[cfg(debug_assertions)]
    dst.assert_contains_next_n_bytes(byte_count);

    unsafe {
        std::ptr::copy_nonoverlapping(src.raw(), dst.raw(), byte_count);
    }
}

#[inline]
#[cfg(not(target_feature = "sse2"))]
fn XXH3_accumulate_512_scalar(acc: &mut Acc, input: Ptr<u8>, secret: Ptr<u8>) {
    // Make sure this gets unrolled or that i >= 0 && i < XXH_ACC_NB is known to LLVM
    for i in 0..XXH_ACC_NB {
        XXH3_scalarRound(acc, input, secret, i);
    }
}

#[inline]
#[cfg(not(target_feature = "sse2"))]
fn XXH3_scalarRound(acc: &mut Acc, input: Ptr<u8>, secret: Ptr<u8>, lane: usize) {
    debug_assert!(lane < XXH_ACC_NB);
    debug_assert!((acc.0.as_ptr() as usize & (XXH_ACC_ALIGN - 1)) == 0);
    {
        let data_val = XXH_readLE64(input.offset(lane * 8));
        let data_key = data_val ^ XXH_readLE64(secret.offset(lane * 8));
        acc.0[lane ^ 1] = acc.0[lane ^ 1].wrapping_add(data_val); /* swap adjacent lanes */
        acc.0[lane] =
            acc.0[lane].wrapping_add(XXH_mult32to64(data_key & 0xFFFFFFFF, data_key >> 32));
    }
}

#[cfg(target_feature = "sse2")]
#[inline]
fn XXH3_accumulate_512_sse2(acc: &mut Acc, input: Ptr<u8>, secret: Ptr<u8>) {
    debug_assert!((acc as *mut _ as usize & 15) == 0);
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        let acc: PtrMut<_> = (&mut acc.0[..]).into();
        let acc: PtrMut<__m128i> = acc.cast();

        // Unaligned. This is mainly for pointer arithmetic, and because
        // _mm_loadu_si128 requires a const __m128i* pointer for some reason.
        let input: Ptr<__m128i> = input.cast();
        // Unaligned. This is mainly for pointer arithmetic, and because
        // _mm_loadu_si128 requires a const __m128i* pointer for some reason.
        let secret: Ptr<__m128i> = secret.cast();

        for i in 0..XXH_STRIPE_LEN / size_of::<__m128i>() {
            // data_vec    = xinput[i];
            let data_vec = _mm_loadu_si128(input.offset(i).raw());
            // key_vec     = xsecret[i];
            let key_vec = _mm_loadu_si128(secret.offset(i).raw());
            // data_key    = data_vec ^ key_vec;
            let data_key = _mm_xor_si128(data_vec, key_vec);
            // data_key_lo = data_key >> 32;
            let data_key_lo = _mm_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));
            // product     = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff);
            let product = _mm_mul_epu32(data_key, data_key_lo);
            // acc[i] += swap(data_vec);
            let data_swap = _mm_shuffle_epi32(data_vec, _mm_shuffle(1, 0, 3, 2));
            let sum = _mm_add_epi64(acc.offset(i).read(), data_swap);
            // acc[i] += product;
            acc.offset(i).write(_mm_add_epi64(product, sum));
        }
    }
}

#[cfg(target_feature = "avx2")]
#[inline]
fn XXH3_accumulate_512_avx2(acc: &mut Acc, input: Ptr<u8>, secret: Ptr<u8>) {
    debug_assert!((acc as *mut _ as usize & 31) == 0);
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        let acc: PtrMut<_> = (&mut acc.0[..]).into();
        let acc: PtrMut<__m256i> = acc.cast();

        // Unaligned. This is mainly for pointer arithmetic, and because
        // _mm256_loadu_si256 requires a const __m256i* pointer for some reason.
        let input: Ptr<__m256i> = input.cast();
        // Unaligned. This is mainly for pointer arithmetic, and because
        // _mm256_loadu_si256 requires a const __m256i* pointer for some reason.
        let secret: Ptr<__m256i> = secret.cast();

        for i in 0..XXH_STRIPE_LEN / size_of::<__m256i>() {
            // data_vec    = xinput[i];
            let data_vec = _mm256_loadu_si256(input.offset(i).raw());
            // key_vec     = xsecret[i];
            let key_vec = _mm256_loadu_si256(secret.offset(i).raw());
            // data_key    = data_vec ^ key_vec;
            let data_key = _mm256_xor_si256(data_vec, key_vec);
            // data_key_lo = data_key >> 32;
            let data_key_lo = _mm256_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));
            // product     = (data_key & 0xffffffff) * (data_key_lo & 0xffffffff);
            let product = _mm256_mul_epu32(data_key, data_key_lo);
            // acc[i] += swap(data_vec);
            let data_swap = _mm256_shuffle_epi32(data_vec, _mm_shuffle(1, 0, 3, 2));
            let sum = _mm256_add_epi64(acc.offset(i).read(), data_swap);
            // acc[i] += product;
            acc.offset(i).write(_mm256_add_epi64(product, sum));
        }
    }
}

#[inline]
fn XXH_readLE64(ptr: Ptr<u8>) -> u64 {
    #[cfg(debug_assertions)]
    ptr.assert_contains_next_n_bytes(8);

    let ptr = ptr.raw() as *const [u8; 8];
    let bytes = unsafe { *ptr };
    u64::from_le_bytes(bytes)
}

#[inline]
fn XXH_readLE32(ptr: Ptr<u8>) -> u32 {
    #[cfg(debug_assertions)]
    ptr.assert_contains_next_n_bytes(4);

    let ptr = ptr.raw() as *const [u8; 4];
    let bytes = unsafe { *ptr };
    u32::from_le_bytes(bytes)
}

#[inline]
fn XXH_mult32to64(x: u64, y: u64) -> u64 {
    (x as u32 as u64).wrapping_mul(y as u32 as u64)
}

#[inline]
fn XXH3_consumeStripes(
    acc: &mut Acc,
    num_stripes_so_far: &mut usize,
    num_stripes_per_block: usize,
    input: Ptr<u8>,
    num_stripes: usize,
    secret: Ptr<u8>,
    secret_limit: usize,
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc,
) {
    debug_assert!(num_stripes <= num_stripes_per_block);
    debug_assert!(*num_stripes_so_far < num_stripes_per_block);
    if num_stripes_per_block - *num_stripes_so_far <= num_stripes {
        /* need a scrambling operation */
        let num_stripes_to_end_of_block = num_stripes_per_block - *num_stripes_so_far;
        let num_stripes_after_block = num_stripes - num_stripes_to_end_of_block;
        XXH3_accumulate(
            acc,
            input,
            secret.offset(*num_stripes_so_far * XXH_SECRET_CONSUME_RATE),
            num_stripes_to_end_of_block,
            f_acc512,
        );
        f_scramble(acc, secret.offset(secret_limit));
        XXH3_accumulate(
            acc,
            input.offset(num_stripes_to_end_of_block * XXH_STRIPE_LEN),
            secret,
            num_stripes_after_block,
            f_acc512,
        );
        *num_stripes_so_far = num_stripes_after_block;
    } else {
        XXH3_accumulate(
            acc,
            input,
            secret.offset(*num_stripes_so_far * XXH_SECRET_CONSUME_RATE),
            num_stripes,
            f_acc512,
        );
        *num_stripes_so_far += num_stripes;
    }
}

#[inline]
fn XXH3_accumulate(
    acc: &mut Acc,
    input: Ptr<u8>,
    secret: Ptr<u8>,
    num_stripes: usize,
    f_acc512: XXH3_f_accumulate_512,
) {
    for n in 0..num_stripes {
        let input = input.offset(n * XXH_STRIPE_LEN);

        // This is taken from the C implementation. Not sure if it is completely safe.
        // It seems to improve performance a little bit, but not much.
        #[cfg(feature = "nightly")]
        #[cfg(not(debug_assertions))]
        unsafe {
            const XXH_PREFETCH_DIST: usize = 320;
            std::intrinsics::prefetch_read_data(input.offset(XXH_PREFETCH_DIST).raw(), 1);
        }

        f_acc512(acc, input, secret.offset(n * XXH_SECRET_CONSUME_RATE));
    }
}

#[inline]
#[cfg(not(target_feature = "sse2"))]
fn XXH3_scrambleAcc_scalar(acc: &mut Acc, secret: Ptr<u8>) {
    for i in 0..XXH_ACC_NB {
        XXH3_scalarScrambleRound(acc, secret, i);
    }
}

#[inline]
#[cfg(not(target_feature = "sse2"))]
fn XXH3_scalarScrambleRound(acc: &mut Acc, secret: Ptr<u8>, lane: usize) {
    debug_assert!(((acc.0.as_ptr() as usize) & (XXH_ACC_ALIGN - 1)) == 0);
    debug_assert!(lane < XXH_ACC_NB);
    {
        let key64 = XXH_readLE64(secret.offset(lane * 8));
        let mut acc64 = acc.0[lane];
        acc64 = XXH_xorshift64(acc64, 47);
        acc64 ^= key64;
        acc64 = acc64.wrapping_mul(XXH_PRIME32_1 as u64);
        acc.0[lane] = acc64;
    }
}

#[inline]
const fn XXH_xorshift64(v64: u64, shift: i32) -> u64 {
    debug_assert!(0 <= shift && shift < 64);
    return v64 ^ (v64 >> shift);
}

#[cfg(target_feature = "sse2")]
#[inline]
fn XXH3_scrambleAcc_sse2(acc: &mut Acc, secret: Ptr<u8>) {
    debug_assert!((acc as *mut _ as usize & 15) == 0);
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        let acc: PtrMut<_> = (&mut acc.0[..]).into();
        let acc: PtrMut<__m128i> = acc.cast();

        // Unaligned. This is mainly for pointer arithmetic, and because
        // _mm_loadu_si128 requires a const __m128i* pointer for some reason.
        let xsecret: Ptr<__m128i> = secret.cast();
        let prime32 = _mm_set1_epi32(XXH_PRIME32_1 as i32);

        for i in 0..XXH_STRIPE_LEN / size_of::<__m128i>() {
            // acc[i] ^= (acc[i] >> 47)
            let acc_vec = acc.offset(i).read();
            let shifted = _mm_srli_epi64(acc_vec, 47);
            let data_vec = _mm_xor_si128(acc_vec, shifted);
            // acc[i] ^= xsecret[i];
            let key_vec = _mm_loadu_si128(xsecret.offset(i).raw());
            let data_key = _mm_xor_si128(data_vec, key_vec);

            // acc[i] *= XXH_PRIME32_1;
            let data_key_hi = _mm_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));
            let prod_lo = _mm_mul_epu32(data_key, prime32);
            let prod_hi = _mm_mul_epu32(data_key_hi, prime32);
            acc.offset(i)
                .write(_mm_add_epi64(prod_lo, _mm_slli_epi64(prod_hi, 32)));
        }
    }
}

#[cfg(target_feature = "avx2")]
#[inline]
fn XXH3_scrambleAcc_avx2(acc: &mut Acc, secret: Ptr<u8>) {
    debug_assert!((acc as *mut _ as usize & 31) == 0);
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        let acc: PtrMut<_> = (&mut acc.0[..]).into();
        let acc: PtrMut<__m256i> = acc.cast();

        // Unaligned. This is mainly for pointer arithmetic, and because
        // _mm256_loadu_si256 requires a const __m256i* pointer for some reason.
        let xsecret: Ptr<__m256i> = secret.cast();
        let prime32 = _mm256_set1_epi32(XXH_PRIME32_1 as i32);

        for i in 0..XXH_STRIPE_LEN / size_of::<__m256i>() {
            // acc[i] ^= (acc[i] >> 47)
            let acc_vec = acc.offset(i).read();
            let shifted = _mm256_srli_epi64(acc_vec, 47);
            let data_vec = _mm256_xor_si256(acc_vec, shifted);
            // acc[i] ^= xsecret[i];
            let key_vec = _mm256_loadu_si256(xsecret.offset(i).raw());
            let data_key = _mm256_xor_si256(data_vec, key_vec);

            // acc[i] *= XXH_PRIME32_1;
            let data_key_hi = _mm256_shuffle_epi32(data_key, _mm_shuffle(0, 3, 0, 1));
            let prod_lo = _mm256_mul_epu32(data_key, prime32);
            let prod_hi = _mm256_mul_epu32(data_key_hi, prime32);
            acc.offset(i)
                .write(_mm256_add_epi64(prod_lo, _mm256_slli_epi64(prod_hi, 32)));
        }
    }
}

const XXH_PRIME32_1: u32 = 0x9E3779B1;
const XXH_PRIME32_2: u32 = 0x85EBCA77;
const XXH_PRIME32_3: u32 = 0xC2B2AE3D;
const _XXH_PRIME32_4: u32 = 0x27D4EB2F;
const _XXH_PRIME32_5: u32 = 0x165667B1;

fn XXH3_mergeAccs(acc: &mut Acc, secret: Ptr<u8>, start: u64) -> u64 {
    let mut result64 = start;
    let acc: Ptr<u64> = acc.0[..].into();

    for i in 0..4 {
        result64 = XXH3_mix2Accs(acc.offset(2 * i), secret.offset(16 * i)).wrapping_add(result64);
    }

    return XXH3_avalanche(result64);
}

#[inline]
fn XXH3_mix2Accs(acc: Ptr<u64>, secret: Ptr<u8>) -> u64 {
    return XXH3_mul128_fold64(
        acc.read() ^ XXH_readLE64(secret),
        acc.offset(1).read() ^ XXH_readLE64(secret.offset(8)),
    );
}

#[inline]
fn XXH3_avalanche(mut h64: u64) -> u64 {
    h64 = XXH_xorshift64(h64, 37);
    h64 = h64.wrapping_mul(0x165667919E3779F9);
    h64 = XXH_xorshift64(h64, 32);
    return h64;
}

#[inline]
fn XXH3_mul128_fold64(lhs: u64, rhs: u64) -> u64 {
    let product = XXH_mult64to128(lhs, rhs);
    return product.low64 ^ product.high64;
}

#[inline]
fn XXH_mult64to128(lhs: u64, rhs: u64) -> Hash128 {
    let product = (lhs as u128).wrapping_mul(rhs as u128);
    Hash128 {
        low64: product as u64,
        high64: (product >> 64) as u64,
    }
}

#[inline(never)]
pub fn XXH3_128bits_withSecret(input: &[u8], secret: &[u8]) -> Hash128 {
    return XXH3_128bits_internal(input, 0, secret, XXH3_hashLong_128b_withSecret);
}

#[inline]
fn XXH3_128bits_internal(
    input: &[u8],
    seed: u64,
    secret: &[u8],
    f_hl128: XXH3_hashLong128_f,
) -> Hash128 {
    debug_assert!(secret.len() >= XXH3_SECRET_SIZE_MIN);

    /*
     * If an action is to be taken if `secret` conditions are not respected,
     * it should be done here.
     * For now, it's a contract pre-condition.
     * Adding a check and a branch here would cost performance at every hash.
     */
    let input_len = input.len();

    if input_len <= 16 {
        return XXH3_len_0to16_128b(input, secret, seed);
    }
    if input_len <= 128 {
        return XXH3_len_17to128_128b(input, secret, seed);
    }
    if input_len <= XXH3_MIDSIZE_MAX as usize {
        return XXH3_len_129to240_128b(input, secret, seed);
    }

    return f_hl128(input, seed, secret);
}

/*
 * Assumption: `secret` size is >= XXH3_SECRET_SIZE_MIN
 */
#[inline]
fn XXH3_len_0to16_128b(input: &[u8], secret: &[u8], seed: u64) -> Hash128 {
    let input_len = input.len();
    debug_assert!(input_len <= 16);
    {
        if input_len > 8 {
            return XXH3_len_9to16_128b(input, secret, seed);
        }
        if input_len >= 4 {
            return XXH3_len_4to8_128b(input, secret, seed);
        }
        if input_len > 0 {
            return XXH3_len_1to3_128b(input, secret, seed);
        }

        let secret: Ptr<u8> = secret.into();
        let bitflipl = XXH_readLE64(secret.offset(64)) ^ XXH_readLE64(secret.offset(72));
        let bitfliph = XXH_readLE64(secret.offset(80)) ^ XXH_readLE64(secret.offset(88));
        Hash128 {
            low64: XXH64_avalanche(seed ^ bitflipl),
            high64: XXH64_avalanche(seed ^ bitfliph),
        }
    }
}

#[inline]
fn XXH64_avalanche(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(XXH_PRIME64_2);
    hash ^= hash >> 29;
    hash = hash.wrapping_mul(XXH_PRIME64_3);
    hash ^= hash >> 32;
    return hash;
}

#[inline]
fn XXH3_len_9to16_128b(input: &[u8], secret: &[u8], seed: u64) -> Hash128 {
    let input_len = input.len();
    let secret: Ptr<u8> = secret.into();
    let input: Ptr<u8> = input.into();
    debug_assert!(9 <= input_len && input_len <= 16);
    {
        let bitflipl =
            (XXH_readLE64(secret.offset(32)) ^ XXH_readLE64(secret.offset(40))).wrapping_sub(seed);
        let bitfliph =
            (XXH_readLE64(secret.offset(48)) ^ XXH_readLE64(secret.offset(56))).wrapping_add(seed);
        let input_lo = XXH_readLE64(input);
        let mut input_hi = XXH_readLE64(input.offset(input_len - 8));
        let mut m128 = XXH_mult64to128(input_lo ^ input_hi ^ bitflipl, XXH_PRIME64_1);
        /*
         * Put len in the middle of m128 to ensure that the length gets mixed to
         * both the low and high bits in the 128x64 multiply below.
         */
        m128.low64 = m128.low64.wrapping_add((input_len as u64 - 1) << 54);
        input_hi ^= bitfliph;
        /*
         * Add the high 32 bits of input_hi to the high 32 bits of m128, then
         * add the long product of the low 32 bits of input_hi and XXH_PRIME32_2 to
         * the high 64 bits of m128.
         *
         * The best approach to this operation is different on 32-bit and 64-bit.
         */
        if cfg!(target_pointer_width = "32") {
            /* 32-bit */
            /*
             * 32-bit optimized version, which is more readable.
             *
             * On 32-bit, it removes an ADC and delays a dependency between the two
             * halves of m128.high64, but it generates an extra mask on 64-bit.
             */
            m128.high64 = m128.high64.wrapping_add(
                (input_hi & 0xFFFFFFFF00000000)
                    .wrapping_add(XXH_mult32to64(input_hi, XXH_PRIME32_2 as u64)),
            );
        } else {
            /*
             * 64-bit optimized (albeit more confusing) version.
             *
             * Uses some properties of addition and multiplication to remove the mask:
             *
             * Let:
             *    a = input_hi.lo = (input_hi & 0x00000000FFFFFFFF)
             *    b = input_hi.hi = (input_hi & 0xFFFFFFFF00000000)
             *    c = XXH_PRIME32_2
             *
             *    a + (b * c)
             * Inverse Property: x + y - x == y
             *    a + (b * (1 + c - 1))
             * Distributive Property: x * (y + z) == (x * y) + (x * z)
             *    a + (b * 1) + (b * (c - 1))
             * Identity Property: x * 1 == x
             *    a + b + (b * (c - 1))
             *
             * Substitute a, b, and c:
             *    input_hi.hi + input_hi.lo + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
             *
             * Since input_hi.hi + input_hi.lo == input_hi, we get this:
             *    input_hi + ((xxh_u64)input_hi.lo * (XXH_PRIME32_2 - 1))
             */
            m128.high64 = m128.high64.wrapping_add(
                input_hi.wrapping_add(XXH_mult32to64(input_hi, XXH_PRIME32_2 as u64 - 1)),
            );
        }

        /* m128 ^= XXH_swap64(m128 >> 64); */
        m128.low64 ^= m128.high64.swap_bytes();

        /* 128x64 multiply: h128 = m128 * XXH_PRIME64_2; */
        let mut h128 = XXH_mult64to128(m128.low64, XXH_PRIME64_2);
        h128.high64 = h128
            .high64
            .wrapping_add(m128.high64.wrapping_mul(XXH_PRIME64_2));

        h128.low64 = XXH3_avalanche(h128.low64);
        h128.high64 = XXH3_avalanche(h128.high64);
        return h128;
    }
}

#[inline]
fn XXH3_len_4to8_128b(input: &[u8], secret: &[u8], mut seed: u64) -> Hash128 {
    let input_len = input.len();
    debug_assert!(4 <= input_len && input_len <= 8);
    let input: Ptr<u8> = input.into();
    let secret: Ptr<u8> = secret.into();

    seed ^= ((seed as u32).swap_bytes() as u64) << 32;

    let input_lo = XXH_readLE32(input);
    let input_hi = XXH_readLE32(input.offset(input_len - 4));
    let input_64 = (input_lo as u64).wrapping_add((input_hi as u64) << 32);
    let bitflip =
        (XXH_readLE64(secret.offset(16)) ^ XXH_readLE64(secret.offset(24))).wrapping_add(seed);
    let keyed = input_64 ^ bitflip;

    /* Shift len to the left to ensure it is even, this avoids even multiplies. */
    let mut m128 = XXH_mult64to128(keyed, XXH_PRIME64_1.wrapping_add((input_len as u64) << 2));

    m128.high64 = m128.high64.wrapping_add(m128.low64 << 1);
    m128.low64 ^= m128.high64 >> 3;

    m128.low64 = XXH_xorshift64(m128.low64, 35);
    m128.low64 = m128.low64.wrapping_mul(0x9FB21C651E98DF25);
    m128.low64 = XXH_xorshift64(m128.low64, 28);
    m128.high64 = XXH3_avalanche(m128.high64);
    return m128;
}

#[inline]
fn XXH3_len_1to3_128b(input: &[u8], secret: &[u8], seed: u64) -> Hash128 {
    let input_len = input.len();
    /* A doubled version of 1to3_64b with different constants. */
    debug_assert!(1 <= input_len && input_len <= 3);

    let input: Ptr<u8> = input.into();
    let secret: Ptr<u8> = secret.into();

    let c1: u8 = input.read();
    let c2: u8 = input.offset(input_len >> 1).read();
    let c3: u8 = input.offset(input_len - 1).read();

    let combinedl: u32 =
        ((c1 as u32) << 16) | ((c2 as u32) << 24) | ((c3 as u32) << 0) | ((input_len as u32) << 8);

    let combinedh: u32 = combinedl.swap_bytes().rotate_left(13);
    let bitflipl: u64 =
        ((XXH_readLE32(secret) ^ XXH_readLE32(secret.offset(4))) as u64).wrapping_add(seed);
    let bitfliph: u64 = ((XXH_readLE32(secret.offset(8)) ^ XXH_readLE32(secret.offset(12))) as u64)
        .wrapping_sub(seed);
    let keyed_lo: u64 = combinedl as u64 ^ bitflipl;
    let keyed_hi: u64 = combinedh as u64 ^ bitfliph;
    Hash128 {
        low64: XXH64_avalanche(keyed_lo),
        high64: XXH64_avalanche(keyed_hi),
    }
}

#[inline]
fn XXH3_len_17to128_128b(input: &[u8], secret: &[u8], seed: u64) -> Hash128 {
    debug_assert!(secret.len() >= XXH3_SECRET_SIZE_MIN);

    let input_len = input.len();
    let input: Ptr<u8> = input.into();
    let secret: Ptr<u8> = secret.into();

    debug_assert!(16 < input_len && input_len <= 128);

    {
        let mut acc = Hash128 {
            low64: (input_len as u64).wrapping_mul(XXH_PRIME64_1),
            high64: 0,
        };

        if input_len > 32 {
            if input_len > 64 {
                if input_len > 96 {
                    acc = XXH128_mix32B(
                        acc,
                        input.offset(48),
                        input.offset(input_len - 64),
                        secret.offset(96),
                        seed,
                    );
                }
                acc = XXH128_mix32B(
                    acc,
                    input.offset(32),
                    input.offset(input_len - 48),
                    secret.offset(64),
                    seed,
                );
            }
            acc = XXH128_mix32B(
                acc,
                input.offset(16),
                input.offset(input_len - 32),
                secret.offset(32),
                seed,
            );
        }
        acc = XXH128_mix32B(acc, input, input.offset(input_len - 16), secret, seed);

        let mut h128 = Hash128 {
            low64: acc.low64.wrapping_add(acc.high64),
            high64: acc
                .low64
                .wrapping_mul(XXH_PRIME64_1)
                .wrapping_add(acc.high64.wrapping_mul(XXH_PRIME64_4))
                .wrapping_add(((input_len as u64).wrapping_sub(seed)).wrapping_mul(XXH_PRIME64_2)),
        };
        h128.low64 = XXH3_avalanche(h128.low64);
        h128.high64 = 0u64.wrapping_sub(XXH3_avalanche(h128.high64));
        return h128;
    }
}

#[inline]
fn XXH128_mix32B(
    mut acc: Hash128,
    input_1: Ptr<u8>,
    input_2: Ptr<u8>,
    secret: Ptr<u8>,
    seed: u64,
) -> Hash128 {
    acc.low64 = acc.low64.wrapping_add(XXH3_mix16B(input_1, secret, seed));
    acc.low64 ^= XXH_readLE64(input_2).wrapping_add(XXH_readLE64(input_2.offset(8)));
    acc.high64 = acc
        .high64
        .wrapping_add(XXH3_mix16B(input_2, secret.offset(16), seed));
    acc.high64 ^= XXH_readLE64(input_1).wrapping_add(XXH_readLE64(input_1.offset(8)));
    return acc;
}

#[inline]
fn XXH3_mix16B(input: Ptr<u8>, secret: Ptr<u8>, seed: u64) -> u64 {
    let input_lo = XXH_readLE64(input);
    let input_hi = XXH_readLE64(input.offset(8));

    XXH3_mul128_fold64(
        input_lo ^ XXH_readLE64(secret).wrapping_add(seed),
        input_hi ^ XXH_readLE64(secret.offset(8)).wrapping_sub(seed),
    )
}

#[inline(never)]
fn XXH3_len_129to240_128b(input: &[u8], secret: &[u8], seed: u64) -> Hash128 {
    let input_len = input.len();
    let input: Ptr<u8> = input.into();

    // NOTE: is secret_size that same as secret.len()
    debug_assert!(secret.len() >= XXH3_SECRET_SIZE_MIN);
    debug_assert!(128 < input_len && input_len <= XXH3_MIDSIZE_MAX as usize);

    let secret: Ptr<u8> = secret.into();

    {
        let num_rounds = input_len / 32;
        let mut acc = Hash128 {
            low64: (input_len as u64).wrapping_mul(XXH_PRIME64_1),
            high64: 0,
        };

        for i in 0..4 {
            acc = XXH128_mix32B(
                acc,
                input.offset(32 * i),
                input.offset((32 * i) + 16),
                secret.offset(32 * i),
                seed,
            );
        }
        acc.low64 = XXH3_avalanche(acc.low64);
        acc.high64 = XXH3_avalanche(acc.high64);
        debug_assert!(num_rounds >= 4);
        for i in 4..num_rounds {
            acc = XXH128_mix32B(
                acc,
                input.offset(32 * i),
                input.offset((32 * i) + 16),
                secret.offset(XXH3_MIDSIZE_STARTOFFSET + (32 * (i - 4))),
                seed,
            );
        }
        /* last bytes */
        acc = XXH128_mix32B(
            acc,
            input.offset(input_len - 16),
            input.offset(input_len - 32),
            secret.offset(XXH3_SECRET_SIZE_MIN - XXH3_MIDSIZE_LASTOFFSET - 16),
            0u64.wrapping_sub(seed),
        );

        {
            let mut h128 = Hash128 {
                low64: acc.low64.wrapping_add(acc.high64),
                high64: acc
                    .low64
                    .wrapping_mul(XXH_PRIME64_1)
                    .wrapping_add(acc.high64.wrapping_mul(XXH_PRIME64_4))
                    .wrapping_add(
                        ((input_len as u64).wrapping_sub(seed)).wrapping_mul(XXH_PRIME64_2),
                    ),
            };
            h128.low64 = XXH3_avalanche(h128.low64);
            h128.high64 = 0u64.wrapping_sub(XXH3_avalanche(h128.high64));
            return h128;
        }
    }
}

#[inline]
fn XXH3_hashLong_128b_withSecret(input: &[u8], seed: u64, secret: &[u8]) -> Hash128 {
    assert!(seed == 0);
    XXH3_hashLong_128b_internal(input, secret, XXH3_accumulate_512, XXH3_scrambleAcc)
}

#[inline]
fn XXH3_hashLong_128b_internal(
    input: &[u8],
    secret: &[u8],
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc,
) -> Hash128 {
    let mut acc: Acc = XXH3_INIT_ACC;

    XXH3_hashLong_internal_loop(&mut acc, input, secret, f_acc512, f_scramble);

    debug_assert!(size_of_val(&acc) == 64);
    debug_assert!(secret.len() >= size_of_val(&acc) + XXH_SECRET_MERGEACCS_START);

    let secret_size = secret.len();
    let secret: Ptr<u8> = secret.into();
    let input_len = input.len();

    {
        Hash128 {
            low64: XXH3_mergeAccs(
                &mut acc,
                secret.offset(XXH_SECRET_MERGEACCS_START),
                XXH_PRIME64_1.wrapping_mul(input_len as u64),
            ),
            high64: XXH3_mergeAccs(
                &mut acc,
                secret.offset(secret_size - size_of::<Acc>() - XXH_SECRET_MERGEACCS_START),
                !XXH_PRIME64_2.wrapping_mul(input_len as u64),
            ),
        }
    }
}

#[inline]
fn XXH3_hashLong_internal_loop(
    acc: &mut Acc,
    input: &[u8],
    secret: &[u8],
    f_acc512: XXH3_f_accumulate_512,
    f_scramble: XXH3_f_scrambleAcc,
) {
    let num_stripes_per_block = (secret.len() - XXH_STRIPE_LEN) / XXH_SECRET_CONSUME_RATE;
    let block_len = XXH_STRIPE_LEN * num_stripes_per_block;

    let input_len = input.len();
    let secret_len = secret.len();

    let secret: Ptr<u8> = secret.into();
    let input: Ptr<u8> = input.into();

    let nb_blocks = (input_len - 1) / block_len;

    debug_assert!(secret_len >= XXH3_SECRET_SIZE_MIN);

    for n in 0..nb_blocks {
        XXH3_accumulate(
            acc,
            input.offset(n * block_len),
            secret,
            num_stripes_per_block,
            f_acc512,
        );
        f_scramble(acc, secret.offset(secret_len - XXH_STRIPE_LEN));
    }

    /* last partial block */
    debug_assert!(input_len > XXH_STRIPE_LEN);
    {
        let num_stripes = ((input_len - 1) - (block_len * nb_blocks)) / XXH_STRIPE_LEN;
        debug_assert!(num_stripes <= (secret_len / XXH_SECRET_CONSUME_RATE));
        XXH3_accumulate(
            acc,
            input.offset(nb_blocks * block_len),
            secret,
            num_stripes,
            f_acc512,
        );

        /* last stripe */
        {
            let p = input.offset(input_len - XXH_STRIPE_LEN);
            // #define XXH_SECRET_LASTACC_START 7  /* not aligned on 8, last secret is different from acc & scrambler */
            f_acc512(
                acc,
                p,
                secret.offset(secret_len - XXH_STRIPE_LEN - XXH_SECRET_LASTACC_START),
            );
        }
    }
}

#[cfg(feature = "support_seed")]
#[cfg(not(target_feature = "sse2"))]
#[inline]
fn XXH3_initCustom_secret_scalar(custom_secret: &mut Secret, seed: u64) {
    /*
     * We need a separate pointer for the hack below,
     * which requires a non-const pointer.
     * Any decent compiler will optimize this out otherwise.
     */
    let kSecretPtr: Ptr<u8> = XXH3_kSecret.as_ptr();
    debug_assert!((XXH_SECRET_DEFAULT_SIZE & 15) == 0);

    // #if defined(__clang__) && defined(__aarch64__)
    //     /*
    //      * UGLY HACK:
    //      * Clang generates a bunch of MOV/MOVK pairs for aarch64, and they are
    //      * placed sequentially, in order, at the top of the unrolled loop.
    //      *
    //      * While MOVK is great for generating constants (2 cycles for a 64-bit
    //      * constant compared to 4 cycles for LDR), it fights for bandwidth with
    //      * the arithmetic instructions.
    //      *
    //      *   I   L   S
    //      * MOVK
    //      * MOVK
    //      * MOVK
    //      * MOVK
    //      * ADD
    //      * SUB      STR
    //      *          STR
    //      * By forcing loads from memory (as the asm line causes Clang to assume
    //      * that XXH3_kSecretPtr has been changed), the pipelines are used more
    //      * efficiently:
    //      *   I   L   S
    //      *      LDR
    //      *  ADD LDR
    //      *  SUB     STR
    //      *          STR
    //      *
    //      * See XXH3_NEON_LANES for details on the pipsline.
    //      *
    //      * XXH3_64bits_withSeed, len == 256, Snapdragon 835
    //      *   without hack: 2654.4 MB/s
    //      *   with hack:    3202.9 MB/s
    //      */
    //     XXH_COMPILER_GUARD(kSecretPtr);
    // #endif
    /*
     * Note: in debug mode, this overrides the asm optimization
     * and Clang will emit MOVK chains again.
     */

    #[cfg(not(miri))] // ??
    debug_assert_eq!(kSecretPtr, XXH3_kSecret.as_ptr());

    {
        let num_rounds = XXH_SECRET_DEFAULT_SIZE / 16;

        let custom_secret: PtrMut<u8> = custom_secret.as_mut_ptr();

        for i in 0..num_rounds {
            /*
             * The asm hack causes Clang to assume that kSecretPtr aliases with
             * custom_secret, and on aarch64, this prevented LDP from merging two
             * loads together for free. Putting the loads together before the stores
             * properly generates LDP.
             */
            let lo = XXH_readLE64(kSecretPtr.offset(16 * i)).wrapping_add(seed);
            let hi = XXH_readLE64(kSecretPtr.offset(16 * i + 8)).wrapping_sub(seed);
            XXH_writeLE64(custom_secret.offset(16 * i), lo);
            XXH_writeLE64(custom_secret.offset(16 * i + 8), hi);
        }
    }
}

#[cfg(feature = "support_seed")]
#[cfg(target_feature = "sse2")]
#[inline]
fn XXH3_initCustom_secret_sse2(custom_secret: &mut Secret, seed: u64) {
    assert!((XXH_SECRET_DEFAULT_SIZE & 15) == 0);

    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::*;
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::*;

        let num_rounds = XXH_SECRET_DEFAULT_SIZE / size_of::<__m128i>();

        let seed = _mm_set_epi64x(0u64.wrapping_sub(seed) as i64, seed as i64);

        // int i;

        // const void* const src16 = XXH3_kSecret;
        let src16: Ptr<u8> = XXH3_kSecret.as_ptr();
        let src16: Ptr<__m128i> = src16.cast();

        let dst16: PtrMut<__m128i>;

        #[cfg(feature = "nightly")]
        {
            //          * On GCC & Clang, marking 'dest' as modified will cause the compiler:
            //          *   - do not extract the secret from sse registers in the internal loop
            //          *   - use less common registers, and avoid pushing these reg into stack
            //          */
            dst16 = std::hint::black_box(custom_secret.as_mut_ptr().cast());
        }

        #[cfg(not(feature = "nightly"))]
        {
            dst16 = custom_secret.as_mut_ptr().cast();
        }

        #[cfg(debug_assertions)]
        {
            assert!((src16.addr() & 15) == 0); /* control alignment */
            assert!((dst16.addr() & 15) == 0);
        }

        for i in 0..num_rounds {
            dst16
                .offset(i)
                .raw()
                .write(_mm_add_epi64(_mm_load_si128(src16.offset(i).raw()), seed));
        }
    }
}

#[cfg(feature = "support_seed")]
#[cfg(not(target_feature = "sse2"))]
#[inline]
fn XXH_writeLE64(dst: PtrMut<u8>, v64: u64) {
    #[cfg(debug_assertions)]
    dst.assert_contains_next_n_bytes(8);

    let ptr = dst.raw() as *mut [u8; 8];
    unsafe {
        *ptr = v64.to_le_bytes();
    }
}

// This is a copy of _MM_SHUFFLE() from stdarch.
// Using the stdarch version would require `feature(stdarch)`.
#[inline]
const fn _mm_shuffle(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}
