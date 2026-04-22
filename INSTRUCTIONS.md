# OrbitSec Contributor Guide

## Setup
1. Install Python dependencies: `pip install -r requirements.txt`.
2. Ensure OpenSSL 3.x is installed.

## Tasks
* **Fuzzer (Jordan):** Create `testing/fuzzer.py`. [cite_start]Mutate `data/ciphertext.bin` and verify the C decoder handles errors without crashing.
* **Benchmarking (Hayden):** Create `testing/bench.py`. [cite_start]Measure latency and throughput of the encryption architecture.
* [cite_start]**Diagrams (Cali):** Create visual maps in `docs/` showing the "Encrypt-then-Sign" and "Verify-then-Decrypt" data flow.