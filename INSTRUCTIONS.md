# OrbitSec Contributor Guide

## Setup
1. **Python**: Install dependencies: `pip install -r requirements.txt`.
2. **OpenSSL**: Ensure OpenSSL 3.x is installed on your system.

## How to Build and Run (C Firmware)
1. Navigate to the `firmware/` directory.
2. **Compile**: Run `make`. 
   * *Note: If you are on Windows, you may need to update the OPENSSL_PATH in the Makefile to match your installation (e.g., C:/Program Files/OpenSSL-Win64).*
3. **Execute**: Run `./orbitsec_decoder`. It will automatically look for the artifacts in the `data/` folder.

## Tasks
* **Fuzzer (Jordan):** * Create `testing/fuzzer.py`. 
  * Mutate `data/ciphertext.bin` by flipping bits in the payload or signature. 
  * **Reference**: See `firmware/include/packet_format.h` for the exact byte offsets.
  * Goal: Ensure the C decoder catches the error and exits gracefully without a segfault.

* **Benchmarking (Hayden):** * Create `testing/bench.py`. 
  * Automate the execution of the Python uplink and C decoder to measure total round-trip latency.
  * Profile the signature verification time vs. decryption time.

* **Diagrams (Cali):** * Create visual maps in `docs/` using Mermaid.js or an image editor.
  * Map the "Encrypt-then-Sign" (Python) and "Verify-then-Decrypt" (C) data flows.
  * **Reference**: See the official PDFs in the `docs/` folder.