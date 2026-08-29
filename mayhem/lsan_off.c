/* mayhem/lsan_off.c — disable LeakSanitizer at BUILD time for every fuzz target.
 *
 * `-Zsanitizer=address` always bundles LSan into ASan; there is no flag that keeps
 * ASan's memory-corruption checks while dropping just leak detection. Leaks are not
 * the bug class this fleet fuzzes for, and LSan's at-exit scan is both noisy on the
 * arena/`Box::leak` patterns near-primitives' decoders allocate through and in
 * conflict with Mayhem's coverage tracer.
 *
 * ASan calls this weak hook at startup; a strong definition linked into the binary
 * wins. This is the ONLY sanctioned way to turn LSan off (SPEC §6.2): NOT a runtime
 * disable/enable wrap, and NOT a compiled-in default-options override — Mayhem alone
 * owns the sanitizer options environment.
 *
 * mayhem/build.sh compiles this and prepends the object to every rustc link via a
 * -Clinker wrapper, so it lands in each fuzz binary. The clean KAT probe is built
 * with RUSTFLAGS unset, so it is unaffected.
 */
int __lsan_is_turned_off(void) { return 1; }
