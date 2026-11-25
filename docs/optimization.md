# Optimization notes: AES-128 on CV32E40P

## 1. Project Background (read this first)

### 1.1 What the project is
This is a **Processor Design Project (PDP)** at TU Delft. The goal is to **accelerate AES-128
encryption** on a RISC-V soft processor by adding **custom cryptographic instructions** to the
CPU and then writing software that uses them, and to **measure the speedup in clock cycles**.

The deliverable is measured in **clock cycles to encrypt one 16-byte block** (lower = better),
verified in **cycle-accurate simulation** and ultimately runnable on a real FPGA.

### 1.2 The hardware platform
- **CPU:** CV32E40P (formerly "RI5CY") — a small, open-source 32-bit RISC-V core.
  - **4-stage, single-issue, in-order pipeline.** "Single-issue, in-order" is critical to
    understand: the CPU executes **at most one instruction at a time, strictly in program order**.
    It cannot run instructions in parallel. This is why several of our optimizations are about
    **removing pipeline stalls** rather than "doing things in parallel."
- **SoC:** the CV32E40P is dropped into a **Xilinx Zynq-7020** FPGA system (`xc7z020`). The Zynq's
  ARM "Processing System" (PS) is used only as a test harness/host; the actual AES runs on the
  RISC-V core in the FPGA fabric (PL).
- **Memory:** instructions and data live in **on-chip Block RAM (BRAM)**. The CPU reaches BRAM
  through an **OBI (Open Bus Interface)** bus and a small adapter module (`core_2_bram`). The
  **read latency of this memory path is a tunable parameter** — and it turns out to matter a lot.
- **Toolchain:** LLVM/Clang for RISC-V, target `rv32imac_zicsr_zkne`, `-O3`.

### 1.3 The custom instructions (RISC-V "Zkne" scalar-crypto extension)
Plain RISC-V has no AES instructions, so AES must be done with hundreds of software operations
(table lookups, Galois-field multiplies, byte shuffles). The project adds the **Zkne extension**,
which provides four hardware instructions, implemented in the CPU's execute stage as a custom
combinational unit (`cv32e40p_aes_unit.sv`):

| Instruction | What it does in **one** instruction |
|-------------|-------------------------------------|
| `aes32esmi` | One AES **middle round** step: SubBytes + ShiftRows + **MixColumns** + AddRoundKey, for one byte lane |
| `aes32esi`  | One AES **final round** step: SubBytes + ShiftRows + AddRoundKey (no MixColumns) |
| `aes32ks1i` | **Key-schedule** helper: RotWord + SubWord + round-constant XOR |
| `aes32ks2`  | **Key-schedule** helper: the XOR combination that produces the next key word |

A full AES-128 encryption is 1 initial AddRoundKey + 9 middle rounds + 1 final round, plus an
11-round key schedule. With these instructions, each round becomes a handful of `aes32*` ops
instead of dozens of software instructions.

### 1.4 The test being measured
- Plaintext: `"Hello, World!000"` (16 bytes)
- Key: `"cese4040password"` (16 bytes)
- Expected ciphertext (little-endian words): `fba50914 714bf41f 2e25aabe aaf9080f`
- The program writes the result to a memory-mapped address and then writes a sentinel
  `0xDEADBEEF` to `0x42002000`. **Hardware counts the clock cycles from CPU fetch-enable until
  that `0xDEADBEEF` write** — that count is the headline number. The testbench also checks the
  produced ciphertext byte-for-byte and prints `Test PASSED`/`FAILED`.

### 1.5 The two source files to know about
- `software/main.c` — the **original, pure-software** AES (software SBOX, `gf_mult`, software
  MixColumns). Kept as the reference baseline. **Not compiled** in the optimized build.
- `software/modified_main.c` — the **optimized** version that calls the hardware `aes32*`
  instructions. The Makefile's `MAIN_SRC := modified_main.c` makes this the file that is actually
  built. So the algorithm was effectively **rewritten** (software math → hardware instructions),
  but as a **new file**, leaving the original intact for comparison.

---

## 2. The Headline Result

| Stage | Cycles | Step saving | What changed |
|-------|-------:|:-----------:|--------------|
| Original pure-software AES | **6120** | baseline | software S-box/GF math |
| Custom HW AES instructions (2-cycle BRAM) | **~1100** | −82% vs 6120 | move AES into the `aes32*` ISA |
| + single-cycle BRAM read | **~700** | −~400 | memory latency 2→1 |
| + explicit full loop unrolling | **~614** | −~86 | immediates + no loop overhead |
| + aligned word access & interleaved scheduling | **~504** | −~110 | `lw`/`sw` + hide pipeline latency |

**One-line story:** moving AES into custom hardware instructions took it from **6120 → ~1100**
cycles; then four micro-architecture/software refinements (memory latency, unrolling, aligned
access, instruction scheduling) took it from **~1100 → ~700 → ~614 → ~504**.

> All numbers come from full cycle-accurate Vivado simulation with byte-exact ciphertext checking.
> **614 and 504 were re-measured in this work**; **~1100 and ~700** are the measured values of the
> earlier intermediate versions.

---

## 3. How We Decided What to Optimize (the diagnosis)

We disassembled the compiled binary and looked at **where the in-order pipeline stalls**. Three
classes of waste stood out, plus one structural software issue:

1. **Memory read latency.** Every instruction fetch and every round-key load goes through the
   BRAM path, which was configured for a **2-cycle** read. On an in-order core, that extra cycle
   is a bubble on *every* memory access — and AES does hundreds of them. → **lower the latency.**
2. **Byte-by-byte memory access.** The compiler didn't know the key/plaintext arrays were aligned,
   so it loaded them one byte at a time (`lbu` ×16 + shifts + ORs) and stored results the same way.
   Loading four 32-bit words took 40+ instructions instead of 4. → **use aligned word access.**
3. **Dependency-chain bubbles.** The four `aes32esmi` ops that build one output column were written
   back-to-back into the *same* register, so each had to wait for the previous one's result. →
   **interleave independent work to hide the latency.**
4. **(Structural) Runtime loops** prevented the round constants and byte-select fields from being
   compile-time immediates. → **fully unroll.**

---

## 4. The Optimizations (file · code · principle · savings)

### Method A — Single-cycle BRAM read latency  ⭐ biggest single win
**File:** `hardware/src/design/zynq_system/riscv_top_bram.v`
**Change:** flip a parameter on both the instruction and data memory adapters.

```verilog
core_2_bram #( .R_LATENCY_IN_CYCLES(2) )  instr_bram_if ( ... );   // before
core_2_bram #( .R_LATENCY_IN_CYCLES(1) )  instr_bram_if ( ... );   // after
core_2_bram #( .R_LATENCY_IN_CYCLES(2) )  data_bram_if  ( ... );   // before
core_2_bram #( .R_LATENCY_IN_CYCLES(1) )  data_bram_if  ( ... );   // after
```

**Savings:** ~1100 → ~700 (≈ −400 cycles) — the single biggest step.

**Principle:** `core_2_bram` is the adapter between the CPU's OBI bus and the Xilinx Block-RAM IP.
`R_LATENCY_IN_CYCLES` tells the adapter how many cycles to wait after issuing a read address before
asserting "data valid" to the CPU. `=2` inserts one extra bubble on *every* read; `=1` matches the
BRAM IP's real 1-cycle output latency and removes that bubble. Because instruction fetch happens
for every instruction and AES loads a round key every round, this single cycle, multiplied by
hundreds of accesses, is the dominant step of the whole journey.

**FPGA safety note:** the BRAM IP's own configuration is already `output-register = off`,
`READ_LATENCY = 1`. Setting the adapter parameter to 1 makes the wrapper timing *consistent* with
the IP's real latency, so it is correct in both simulation and on real silicon.

---

### Method B — Explicit full loop unrolling  (≈ −86 cycles)
**File:** `software/modified_main.c`
**Change:** replace runtime loops with fully unrolled macros so every index, round constant
(`rnum`), and byte-select (`bs`) is a compile-time constant.

```c
/* Key schedule: 10 rounds unrolled; rnum is an immediate */
#define KS_ROUND(base, rnum) do {                              \
    uint32_t _t = AES32KS1I(rk[(base)+3], rnum);               \
    rk[(base)+4] = AES32KS2(rk[(base)+0], _t);                 \
    rk[(base)+5] = AES32KS2(rk[(base)+1], rk[(base)+4]);       \
    rk[(base)+6] = AES32KS2(rk[(base)+2], rk[(base)+5]);       \
    rk[(base)+7] = AES32KS2(rk[(base)+3], rk[(base)+6]);       \
} while (0)
KS_ROUND(0,0); KS_ROUND(4,1); /* ... */ KS_ROUND(36,9);

/* Encryption: 9 middle rounds + 1 final round, unrolled */
#define MR(n) aes_round(&a0,&a1,&a2,&a3, rk + (n)*4)
MR(1); MR(2); /* ... */ MR(9);
aes_final_round(&a0,&a1,&a2,&a3, rk+40);
```

**Principle:** the `aes32ks1i` round-constant index (`rnum`, 0–9) and the `aes32esmi/esi`
byte-select (`bs`, 0–3) **must be encoded into the instruction's immediate field**. They can only
be immediates if they are compile-time constants, which requires unrolling. Unrolling also removes
loop counters/branches and lets the compiler use the tightest addressing for each `rk[]` offset.
This step takes ~700 → ~614.

---

### Method C — Aligned 32-bit word load/store  (≈ −96 cycles)
**File:** `software/modified_main.c`
**Change:** align the byte arrays and tell the compiler they're aligned, so it emits single
`lw`/`sw` instead of byte loops.

```c
__attribute__((aligned(4))) uint8_t plaintext[16]  = { ... };
__attribute__((aligned(4))) uint8_t key[16]        = { ... };
__attribute__((aligned(4))) uint8_t ciphertext[16] = { 0 };

static inline uint32_t load32_le(const void *p){
    uint32_t v; __builtin_memcpy(&v, __builtin_assume_aligned(p,4), 4); return v;
}
static inline void store32_le(void *p, uint32_t v){
    __builtin_memcpy(__builtin_assume_aligned(p,4), &v, 4);
}
```

**Effect (disassembly):**
```
before:  lbu ×16 + slli + or ...   ; ~40 instructions to load 4 words
         srli + sb ×16             ; ~28 instructions to store 4 words
after:   lw, lw, lw, lw            ; 4 instructions
         sw, sw, sw, sw            ; 4 instructions
```

**Principle:** without an alignment guarantee, the compiler conservatively assumes the `uint8_t[16]`
arrays might be unaligned and reads/writes them one byte at a time, reassembling 32-bit words with
shifts and ORs. `aligned(4)` + `__builtin_assume_aligned` let it prove that a single wide `lw`/`sw`
is safe. **Category: fewer instructions / coalesced memory access.**

---

### Method D — Interleaved column scheduling (hide pipeline latency)  (≈ −14 cycles)
**File:** `software/modified_main.c` (functions `aes_round` / `aes_final_round`)
**Change:** compute the four output columns **interleaved** instead of finishing one column at a
time. The byte-to-column mapping is **identical** — only the order changes.

```c
const uint32_t x0=*a0,x1=*a1,x2=*a2,x3=*a3;
uint32_t t0=rk[0], t1=rk[1], t2=rk[2], t3=rk[3];
t0=ESMI(t0,x0,0); t1=ESMI(t1,x1,0); t2=ESMI(t2,x2,0); t3=ESMI(t3,x3,0);
t0=ESMI(t0,x1,1); t1=ESMI(t1,x2,1); t2=ESMI(t2,x3,1); t3=ESMI(t3,x0,1);
t0=ESMI(t0,x2,2); t1=ESMI(t1,x3,2); t2=ESMI(t2,x0,2); t3=ESMI(t3,x1,2);
t0=ESMI(t0,x3,3); t1=ESMI(t1,x0,3); t2=ESMI(t2,x1,3); t3=ESMI(t3,x2,3);
```

**Principle:** an instruction's result is not usable by the *very next* instruction without a
"result-use" latency penalty (a pipeline bubble). The old code chained four `aes32esmi` into the
same `t0`, so each waited on the previous one. Interleaving t0–t3 means that by the time `t0` is
used again, it was produced **three instructions earlier**, so the latency is fully hidden by
independent work. As a bonus the compiler also hoists the `lw` of the next round key earlier,
removing load-use stalls.

> **Important framing for the talk:** this is **instruction scheduling that exploits
> instruction-level parallelism (ILP) to hide latency**, *not* true parallel execution. On a
> single-issue in-order core, only one instruction issues per cycle — the win is the **removal of
> stall bubbles**, not "running multiple ops at once."

---

## 5. Summary Table (good for one slide)

| Method | Stage | File changed | Category | Cycles saved |
|--------|-------|--------------|----------|--------------|
| A. BRAM read latency 2→1 | ~1100 → ~700 | `riscv_top_bram.v` (2 params) | Hardware memory timing | ≈ 400 |
| B. Explicit full unroll | ~700 → ~614 | `modified_main.c` | SW structure / immediate encoding | ≈ 86 |
| C. Aligned `lw`/`sw` | ~614 → ~518 | `modified_main.c` | Fewer instructions / coalesced access | ≈ 96 |
| D. Interleaved scheduling | ~518 → ~504 | `modified_main.c` | Instruction scheduling / ILP latency hiding | ≈ 14 |

**Only one software file (`modified_main.c`) and one hardware file (`riscv_top_bram.v`, two
parameters) were changed for the 1100→504 journey.** No hand-written assembly — all software gains
come from writing C that guides `clang -O3` to emit better code.

---

## 6. Verification Methodology (for credibility on a slide)

- **Cycle count** is produced by hardware, not by guesswork: a counter measures fetch-enable → the
  `0xDEADBEEF` end-sentinel write.
- Every reported number comes from a **full Vivado batch simulation** that (1) re-bakes the new
  program into the BRAM from the freshly compiled `.coe`, (2) re-elaborates, and (3) runs to
  completion. The testbench independently checks the ciphertext byte-for-byte.
- Final 504-cycle run: ciphertext `fba50914 714bf41f 2e25aabe aaf9080f` matched expected, `Test PASSED`.

---

## 7. Honesty / Limitations (worth a backup slide)

- **614 and 504** were re-measured in this work and are solid.
- **~1100 and ~700** are the measured values of the earlier intermediate versions (custom-ISA
  baseline with 2-cycle memory, and after the single-cycle-memory change). The one-line
  `R_LATENCY 2→1` diff is confirmed in git.
- The per-method savings (≈400 / ≈86 / ≈96 / ≈14) are derived from these stage measurements;
  the ≈96 / ≈14 split inside the final 614→504 step is an estimate from instruction-count analysis.
- A **further idea (on-the-fly key schedule)** was prototyped: it computes round keys inside the
  encryption loop instead of pre-storing all 44 words, eliminating ~80 round-key store/load ops.
  Static analysis shows ~289 vs ~483 core instructions (promising), but it could not be measured
  cleanly in time and was **not adopted**. It is a candidate for future work.

---

## 8. Side-Channel Security: Current Status and Possible Improvements

Performance is only half the story for a crypto accelerator — a real deployment must also resist
**side-channel attacks (SCA)**, where an adversary recovers the secret key not by breaking the math
but by observing physical leakage (timing, power, electromagnetic emanation) or by injecting faults.
This section is meant to be one dedicated slide.

### 8.1 What our design already does well
- **Timing / cache attacks are largely eliminated by construction.** Classical software AES uses
  **T-tables / S-box lookups in memory**, whose access pattern depends on secret data — the basis
  of well-known cache-timing attacks (Bernstein, Prime+Probe, etc.). Our `aes32*` instructions
  implement the S-box as **combinational logic inside the CPU**, with **fixed latency and no
  data-dependent memory access**. This makes the data path **constant-time and table-free**, which
  is the single most important software-level SCA hardening — and we get it "for free" from the
  custom ISA.
- **Constant-time result check.** The ciphertext verification accumulates differences with XOR/OR
  (no secret-dependent early-exit branch), avoiding a timing side channel in the comparison itself.

### 8.2 What is still vulnerable, and how to improve it
Even with a constant-time data path, the **physical** leakage of the hardware AES unit remains.
Concrete, processor-design-level improvements:

| Threat | Why our design is still exposed | Countermeasure to add |
|--------|--------------------------------|-----------------------|
| **Power / EM analysis (DPA, CPA)** | The AES unit's switching activity correlates with intermediate values (Hamming weight/distance), so averaging many traces can recover the key | **Masking** the S-box (first-order Boolean masking, or a **Threshold Implementation / TI** that is provably first-order secure); requires a **fresh-randomness source (TRNG/PRNG)** on the FPGA |
| **Power analysis (hiding angle)** | Leakage is concentrated and low-noise | **Hiding**: power balancing (dual-rail/WDDL logic), random dummy rounds, randomized instruction timing/shuffling of the 16 byte-lane operations |
| **Fault injection (DFA)** | A single induced fault in round 9/10 can leak the key (differential fault analysis) | **Redundancy + detection**: compute twice and compare, parity/ECC on the datapath, or encrypt-then-decrypt verification before releasing ciphertext |
| **Key material in memory** | Round keys are expanded into BRAM in plaintext and persist | **Minimize key lifetime**: prefer **on-the-fly key schedule** (keys live only in registers), scrub registers/memory after use, avoid spilling key words to the stack |
| **Micro-architectural leakage** | If later integrated into a system with caches/branch predictors | Keep the crypto path isolated; ensure no secret-dependent branches in the surrounding C |

### 8.3 The key architectural recommendation
The cleanest path to a side-channel-resistant version is a **masked / threshold implementation of
the S-box inside `cv32e40p_aes_unit.sv`**, fed by an on-chip RNG, combined with an **on-the-fly key
schedule** so secret key material never leaves the register file. This trades area and some
performance for provable first-order resistance — a classic, defensible processor-design trade-off
to present.

---

## 9. Future Work

A dedicated "future work" slide. Ordered roughly by effort/impact:

1. **On-the-fly key schedule (performance + security).** Derive each round key in registers inside
   the encryption loop instead of pre-expanding 44 words to memory. Static analysis already shows
   ~289 vs ~483 core instructions (potential further cycle reduction) **and** it shrinks the key's
   memory footprint, helping SCA. Prototyped here; needs a clean cycle-accurate measurement.
2. **Side-channel-hardened variant.** Add a masked/Threshold-Implementation S-box plus an on-chip
   TRNG/PRNG; quantify the area/timing/cycle cost and validate with a leakage assessment (e.g.
   TVLA).
3. **Full AES coverage.** Add **decryption** instructions (`aes32dsmi`/`aes32dsi`) and support
   **AES-192/256**, then real cipher **modes** (CBC, CTR, GCM) rather than a single ECB block.
4. **Throughput scaling.** Streaming/DMA interface for bulk data, and exploiting block-level
   parallelism (e.g. CTR mode) so multiple blocks overlap.
5. **FPGA implementation results.** Take the design through full synthesis/place-and-route and
   report **post-implementation Fmax, LUT/FF/BRAM utilization, and power**, to complement the
   cycle-count (the project already produces a `timing_summary_impl.txt`).
6. **Verification & robustness.** Formal verification of the `aes32*` unit against the AES spec,
   and a broader test-vector suite (NIST KATs) beyond the single demo vector.

---

