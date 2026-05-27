use std::hint::black_box;
use std::path::PathBuf;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sha2::{Digest, Sha256};
use tokio::runtime::Runtime;

/// Shell-based SHA-256 (legacy method)
async fn shell_based_sha256(path: &PathBuf) -> String {
    let output = tokio::process::Command::new("sha256sum")
        .arg(path)
        .output()
        .await
        .unwrap();

    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap()
        .to_string()
}

/// Streaming SHA-256 (new method) - using sync I/O in blocking task
async fn streaming_sha256(path: &PathBuf) -> String {
    let path = path.clone();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;

        let mut file = std::fs::File::open(&path).unwrap();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = file.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        hex::encode(hasher.finalize())
    })
    .await
    .unwrap()
}

/// Create test file of given size in MB
async fn create_test_file(size_mb: usize) -> PathBuf {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    // Use sync I/O for file creation
    std::thread::spawn({
        let path = path.clone();
        move || {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).unwrap();
            let chunk = vec![0xABu8; 1024 * 1024];

            for _ in 0..size_mb {
                f.write_all(&chunk).unwrap();
            }
        }
    })
    .join()
    .unwrap();

    // Prevent tmp from being dropped
    std::mem::forget(tmp);
    path
}

fn hash_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("hash_performance");

    for size_mb in [10, 50, 100].iter() {
        let path = rt.block_on(create_test_file(*size_mb));

        group.bench_with_input(BenchmarkId::new("shell_based", size_mb), &path, |b, p| {
            b.to_async(&rt)
                .iter(|| async { black_box(shell_based_sha256(p).await) });
        });

        group.bench_with_input(BenchmarkId::new("streaming", size_mb), &path, |b, p| {
            b.to_async(&rt)
                .iter(|| async { black_box(streaming_sha256(p).await) });
        });
    }

    group.finish();
}

criterion_group!(benches, hash_benchmark);
criterion_main!(benches);
