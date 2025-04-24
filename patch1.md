# Patch 1: Add Blake3 & Dilithium Test Harness

This patch introduces basic end-to-end validation for the new quantum-safe primitives:

1. **Unit Tests (Boost.Test)**
   - src/test/blake3_basic_tests.cpp: Verifies Blake3 hashing (idempotence, differing inputs).
   - src/test/dilithium_key_tests.cpp: Exercises OQS/OpenSSL Dilithium3 keygen, export/import, sign, and verify.
   - Updates `src/test/CMakeLists.txt` to include these new test sources in the `test_bitcoin` target.

2. **Fuzz Target (libFuzzer)**
   - src/test/fuzz/qubit_blake3_fuzz.cpp: A minimal fuzz harness driving the Blake3 C API through arbitrary inputs.
   - Updates `src/test/fuzz/CMakeLists.txt` to add `qubit_blake3_fuzz.cpp` to the `fuzz` executable.

**How to Run**
  - Reconfigure and build:
    ```
    mkdir build && cd build
    cmake ..
    make -j
    ```
  - Run Boost unit tests:
    ```
    ctest -R blake3_tests
    ctest -R dilithium_tests
    ```
  - Run fuzz target under libFuzzer (via `llvm-fuzzer` or CTest integration):
    ```
    ./src/test/fuzz/fuzz --runs=0 qubit_blake3_fuzz
    ```

These additions provide CI-friendly smoke checks of Blake3 and Dilithium functionality, forming the basis for subsequent consensus-level integration and validation.