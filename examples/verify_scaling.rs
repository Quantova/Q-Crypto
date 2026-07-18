// Isolate the parallel signature verification from the harness and measure whether it
// scales across the cores or plateaus. Verifies a fixed batch of module lattice
// signatures across a range of thread counts, then optionally sustains the widest count
// so an external sampler can read which cores actually fire.
use qtv_crypto::ml_dsa;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let n = 250usize;
    let ctx: &[u8] = b"";
    let items: Vec<(ml_dsa::PublicKey, Vec<u8>, ml_dsa::Signature)> = (0..n)
        .map(|i| {
            let mut seed = [0u8; 32];
            seed[0] = i as u8;
            seed[1] = (i >> 8) as u8;
            let (pk, sk) = ml_dsa::keygen(&seed);
            let msg = format!("benchmark message number {i}").into_bytes();
            let rnd = [7u8; 32];
            let sig = ml_dsa::sign(&sk, &msg, ctx, &rnd).expect("sign");
            (pk, msg, sig)
        })
        .collect();

    let verify_all = |cores: usize| {
        if cores <= 1 {
            for (pk, msg, sig) in &items {
                assert!(ml_dsa::verify(pk, msg, sig, ctx));
            }
        } else {
            let chunk = n.div_ceil(cores);
            thread::scope(|s| {
                for c in items.chunks(chunk) {
                    s.spawn(move || {
                        for (pk, msg, sig) in c {
                            assert!(ml_dsa::verify(pk, msg, sig, ctx));
                        }
                    });
                }
            });
        }
    };

    println!(
        "available_parallelism = {}",
        thread::available_parallelism().map(|x| x.get()).unwrap_or(0)
    );
    let mut base = Duration::from_secs(1);
    for cores in [1usize, 2, 3, 4, 8, 16, 24] {
        verify_all(cores);
        let iters = 30u32;
        let start = Instant::now();
        for _ in 0..iters {
            verify_all(cores);
        }
        let per = start.elapsed() / iters;
        if cores == 1 {
            base = per;
        }
        let speedup = base.as_secs_f64() / per.as_secs_f64();
        println!("cores={cores:2} per_batch_ms={:7.2} speedup={speedup:.1}x", per.as_secs_f64() * 1000.0);
    }

    if std::env::args().any(|a| a == "sustain") {
        println!("sustaining 24-thread verify for 15s, sample per-core now");
        let end = Instant::now() + Duration::from_secs(15);
        while Instant::now() < end {
            verify_all(24);
        }
        println!("sustain done");
    }
}
