Migration to native C++ (OpenSSL) — style notes
===============================================

Overview
--------
This project is being migrated from Java/SpongyCastle to native C++ using OpenSSL. The goal is an incremental, safe migration: keep a clear native vs Java fallback boundary, avoid exposing C++ functions to public/JS consumers, and remove SpongyCastle only when the native implementation is fully validated.

Core principles
---------------
- Keep explicit if/else branches in Kotlin to show whether native code is used:
  - `if (NativeSeaModule.useNativeCrypto) { /* native */ } else { /* java fallback */ }`
  - This makes it visually obvious which code paths are ported and which are still Java.
- Do not expose native/C++ functions directly to public APIs (JS/React Native). Keep native JNI methods private and wrapped by controlled Kotlin functions (e.g. `SEAWork.pbkdf2(...)`).
- Prefer deterministic encodings and names: always use `StandardCharsets.UTF_8` when converting strings to bytes, and Base64 encode results with `Base64.NO_WRAP` on the Kotlin side.

Why the explicit if/else matters
--------------------------------
- Readability: reviewers can immediately tell what’s ported.
- Safety: you can keep the Java fallback available during development and CI without changing runtime behavior.
- Gradual removal: as each native routine is validated, move the `else` Java block to removal in one commit.

Native API exposure rules
-------------------------
- JNI methods should be `private` and only callable from internal Kotlin helpers.
- Native signatures should use non-null types where possible. Example recommended signatures:

  - `private external fun nativeDigest(algo: String, data: ByteArray): ByteArray`
  - `private external fun nativePbkdf2(pwd: String, salt: ByteArray, iter: Int, keyLenBytes: Int): ByteArray`

- Note: prefer `keyLenBytes` in native API (OpenSSL expects bytes). If you keep `bits` in Kotlin, convert to bytes before calling JNI and document the conversion.

Algorithm name and canonicalization
----------------------------------
- Accept and canonicalize common algorithm names (`"SHA-256"`, `"SHA256"`, `"sha256"`) on the native side or in a thin Kotlin helper.
- Map to OpenSSL EVP names internally (e.g., `EVP_sha256()`).

Error handling and fallbacks
---------------------------
- Native code should signal errors clearly. Prefer throwing Java exceptions via JNI rather than returning `null` silently.
- In Kotlin, catch native exceptions and decide explicitly whether to:
  - Fall back to Java implementation (recommended for dev), or
  - Rethrow/propagate an error for production-critical failures.
- Consider adding a `NativeSeaModule.forceJavaFallback` flag for testing.

Units & conversions
-------------------
- Be explicit about units: PBKDF2 key length is commonly specified in bytes for OpenSSL and in bits in some Java libraries. Convert at the JNI boundary and document which unit the native function expects.

Threading and performance
-------------------------
- PBKDF2 (high iteration counts) can be expensive. Ensure heavy native calls are not run on the UI thread. Either document that callers must dispatch to a background thread, or perform the work asynchronously in native code.

Java fallback considerations
--------------------------
- While migrating, keep the Java fallback intact as an explicit `else` branch.
- When removing SpongyCastle, prefer `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")` (platform API) where available to avoid third-party deps.

Validation and testing checklist
-------------------------------
- Unit tests: compare outputs of Java fallback and native outputs for the same inputs (salt, password, iterations, key length). Use deterministic salt encodings.
- Cross-check: Base64-encode outputs on the Kotlin side and compare strings to validate exact byte equality.
- Edge cases: test empty salts, salts passed as comma-separated byte lists, and very large iteration counts.

Checklist before removing Java fallback / SpongyCastle
-----------------------------------------------------
- All native routines implemented and covered by unit tests.
- Native code returns identical bytes to Java for a wide range of inputs.
- Error handling is mapped (native errors become clear Java exceptions).
- Build infra: native libraries are produced for all target ABIs and CI builds include them.
- Performance: PBKDF2 runtime and memory usage acceptable for target devices.

Quick migration tips
--------------------
- Convert `SEAWork` native PBKDF2 to call OpenSSL `PKCS5_PBKDF2_HMAC(...)` and ensure `keylen` is bytes.
- Implement digest with OpenSSL EVP and canonicalize algorithm names.
- Keep `native` methods private; provide a single public Kotlin wrapper that encodes/decodes and decides fallback.

Use current, non-deprecated OpenSSL APIs
---------------------------------------
- Target modern, supported OpenSSL APIs and avoid deprecated legacy interfaces. For PBKDF2 and digests prefer:
  - `PKCS5_PBKDF2_HMAC` (for PBKDF2-HMAC-SHA256) or the higher-level `EVP_KDF`/`EVP_MAC` interfaces on OpenSSL 3.x when appropriate.
  - EVP digest APIs (e.g. `EVP_sha256()` / `EVP_Digest*` / `EVP_MD_CTX_new` / `EVP_DigestSign*`) rather than low-level or removed functions.
- Be mindful of OpenSSL provider/model changes in 3.x — use documented, supported patterns and test against your minimum supported OpenSSL version.

Migration = rewrite allowed
--------------------------
- The migration does not have to be a strict one-for-one port of Java/SpongyCastle calls. Rewrites are acceptable and often preferable when:
  - Native/OpenSSL offers clearer or more efficient APIs.
  - You can simplify error handling, threading, or memory management in C++.
  - You can consolidate multiple Java helpers into a smaller, safer native surface that achieves the same semantic goals.
- Keep behavioral compatibility (same input/output bytes) for tests and consumers, but feel free to change internals to use modern native idioms and safer APIs.

Example local testing command
-----------------------------
Run a local unit test that calls both `SEAWork.pbkdf2(...)` with `NativeSeaModule.useNativeCrypto = true` and `false` and compare Base64 outputs.

Command to run tests
--------------------
Use `npm test`, this uses test-moniker to build, install, and capture logs, for the e2e app
