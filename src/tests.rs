use crate::{test_data::SINGLE_SHOT_U128, Hash128, Xxh3Hasher};

fn test_128(
    bytes: &[u8],
    seed: u64,
    expected_hash: Hash128,
    hash_fn: &dyn Fn(&[u8], u64) -> Hash128,
) {
    let actual_hash = hash_fn(bytes, seed);

    assert!(
        actual_hash == expected_hash,
        "Hash mismatch for input with length {} and seed {}",
        bytes.len(),
        seed
    );
}

fn for_each_test_config(f: &dyn Fn(&[u8], u64, Hash128)) {
    for &(bytes, hashes) in SINGLE_SHOT_U128 {
        for (seed, low64, high64) in hashes {
            if cfg!(not(feature = "support_seed")) && seed != 0 {
                continue;
            }

            f(bytes, seed, Hash128 { low64, high64 });
        }
    }
}

fn test_streaming(accesses: &[usize], seeds: &[u64]) {
    for_each_test_config(&|bytes, seed, expected_hash| {
        if !seeds.contains(&seed) {
            return;
        }

        test_128(bytes, seed, expected_hash, &|mut bytes, _seed| {
            let mut state = Xxh3Hasher::default();

            #[cfg(feature = "support_seed")]
            {
                if _seed != 0 {
                    state.reset_with_seed(_seed);
                }
            }

            let mut access_index = 0;

            while bytes.len() > 0 {
                let chunk_len = std::cmp::min(accesses[access_index], bytes.len());

                state.update(&bytes[..chunk_len]);

                bytes = &bytes[chunk_len..];
                access_index = (access_index + 1) % accesses.len();
            }

            let hash = state.digest128();

            hash
        });
    });
}

#[test]
fn single_shot_128_no_seed() {
    for_each_test_config(&|bytes, seed, hash| {
        if seed == 0 {
            test_128(bytes, seed, hash, &|bytes, _| crate::XXH3_128bits(bytes));
        }
    });
}

#[cfg_attr(not(feature = "support_seed"), ignore)]
#[test]
fn single_shot_128_with_seed() {
    #[cfg(feature = "support_seed")]
    for_each_test_config(&|bytes, seed, hash| {
        test_128(bytes, seed, hash, &|bytes, seed| {
            crate::XXH3_128bits_withSeed(bytes, seed)
        });
    });
}

#[test]
fn streaming_128_no_seed() {
    test_streaming(&[1, 2, 3, 4], &[0]);
    test_streaming(&[4, 8, 1, 2, 16, 17], &[0]);
    test_streaming(&[usize::MAX], &[0]);
    test_streaming(&[1], &[0]);
}

#[cfg_attr(not(feature = "support_seed"), ignore)]
#[test]
fn streaming_128_with_seed() {
    #[cfg(feature = "support_seed")]
    {
        test_streaming(&[1, 2, 3, 4], &[0, 0x7caeb08cde6e6c4a, 0x64812f7fa7ec4da4]);
        test_streaming(
            &[4, 8, 1, 2, 16, 17],
            &[0, 0x7caeb08cde6e6c4a, 0x64812f7fa7ec4da4],
        );
        test_streaming(&[usize::MAX], &[0, 0x7caeb08cde6e6c4a, 0x64812f7fa7ec4da4]);
        test_streaming(&[1], &[0, 0x7caeb08cde6e6c4a, 0x64812f7fa7ec4da4]);
    }
}
