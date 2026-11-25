/*
 * AES-128 ECB — RISC-V Zkn scalar crypto extension
 * Optimized v2: aligned word load/store (lw/sw instead of lbu/sb),
 *               interleaved round columns to break ESMI/ESI dependency
 *               chains, full loop unroll, hardware key schedule.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BASE_ADDR_DATA 0x42000000
#define BASE_ADDR_END  (BASE_ADDR_DATA + 0x2000)

/* ---- Aligned word load/store (folds to single lw/sw) ------------------ */

static __attribute__((always_inline)) inline uint32_t
load32_le(const void *p)
{
    uint32_t v;
    __builtin_memcpy(&v, __builtin_assume_aligned(p, 4), 4);
    return v;
}

static __attribute__((always_inline)) inline void
store32_le(void *p, uint32_t v)
{
    __builtin_memcpy(__builtin_assume_aligned(p, 4), &v, 4);
}

/* ---- RISC-V Zkn instruction macros ----------------------------------- */

#define AES32ESMI(rs1, rs2, bs)                                         \
  ({                                                                    \
    uint32_t _rd;                                                       \
    __asm__ volatile("aes32esmi %0, %1, %2, " #bs                       \
                     : "=r"(_rd) : "r"(rs1), "r"(rs2));                 \
    _rd;                                                                \
  })

#define AES32ESI(rs1, rs2, bs)                                          \
  ({                                                                    \
    uint32_t _rd;                                                       \
    __asm__ volatile("aes32esi %0, %1, %2, " #bs                        \
                     : "=r"(_rd) : "r"(rs1), "r"(rs2));                 \
    _rd;                                                                \
  })

#define AES32KS1I(rs1, rnum)                                            \
  ({                                                                    \
    uint32_t _rd;                                                       \
    __asm__ volatile(".insn r 0x33, 0x0, 0x18, %0, %1, x" #rnum        \
                     : "=r"(_rd) : "r"(rs1));                           \
    _rd;                                                                \
  })

#define AES32KS2(rs1, rs2)                                              \
  ({                                                                    \
    uint32_t _rd;                                                       \
    __asm__ volatile(".insn r 0x33, 0x0, 0x19, %0, %1, %2"             \
                     : "=r"(_rd) : "r"(rs1), "r"(rs2));                 \
    _rd;                                                                \
  })

/* ---- Key schedule (hardware, fully unrolled) ------------------------- */

void expand_key_u32(const uint8_t *__restrict__ key,
                    uint32_t rk[__restrict__ 44])
{
    rk[0] = load32_le(key +  0);
    rk[1] = load32_le(key +  4);
    rk[2] = load32_le(key +  8);
    rk[3] = load32_le(key + 12);

#define KS_ROUND(base, rnum)                        \
    do {                                            \
        uint32_t _t = AES32KS1I(rk[(base)+3], rnum);\
        rk[(base)+4] = AES32KS2(rk[(base)+0], _t); \
        rk[(base)+5] = AES32KS2(rk[(base)+1], rk[(base)+4]); \
        rk[(base)+6] = AES32KS2(rk[(base)+2], rk[(base)+5]); \
        rk[(base)+7] = AES32KS2(rk[(base)+3], rk[(base)+6]); \
    } while (0)

    KS_ROUND( 0, 0);
    KS_ROUND( 4, 1);
    KS_ROUND( 8, 2);
    KS_ROUND(12, 3);
    KS_ROUND(16, 4);
    KS_ROUND(20, 5);
    KS_ROUND(24, 6);
    KS_ROUND(28, 7);
    KS_ROUND(32, 8);
    KS_ROUND(36, 9);

#undef KS_ROUND

    /* Hardware sentinel — preserved verbatim */
    *(volatile uint32_t *)(0x42002008) = 0xAAAAAAAA;
}

/* ---- AES middle round (SubBytes+ShiftRows+MixColumns+AddRoundKey) -----
 * The four output columns are computed in an interleaved order so that two
 * consecutive uses of the same accumulator (t0..t3) are separated by three
 * independent ESMI instructions, hiding the result-use latency.
 * The byte->column mapping is identical to the straight-line version.
 */

static __attribute__((always_inline)) inline void
aes_round(uint32_t *__restrict__ a0, uint32_t *__restrict__ a1,
          uint32_t *__restrict__ a2, uint32_t *__restrict__ a3,
          const uint32_t *__restrict__ rk)
{
    const uint32_t x0 = *a0, x1 = *a1, x2 = *a2, x3 = *a3;

    uint32_t t0 = rk[0], t1 = rk[1], t2 = rk[2], t3 = rk[3];

    t0 = AES32ESMI(t0, x0, 0); t1 = AES32ESMI(t1, x1, 0);
    t2 = AES32ESMI(t2, x2, 0); t3 = AES32ESMI(t3, x3, 0);

    t0 = AES32ESMI(t0, x1, 1); t1 = AES32ESMI(t1, x2, 1);
    t2 = AES32ESMI(t2, x3, 1); t3 = AES32ESMI(t3, x0, 1);

    t0 = AES32ESMI(t0, x2, 2); t1 = AES32ESMI(t1, x3, 2);
    t2 = AES32ESMI(t2, x0, 2); t3 = AES32ESMI(t3, x1, 2);

    t0 = AES32ESMI(t0, x3, 3); t1 = AES32ESMI(t1, x0, 3);
    t2 = AES32ESMI(t2, x1, 3); t3 = AES32ESMI(t3, x2, 3);

    *a0 = t0; *a1 = t1; *a2 = t2; *a3 = t3;
}

/* ---- AES final round (SubBytes+ShiftRows+AddRoundKey, no MixColumns) -- */

static __attribute__((always_inline)) inline void
aes_final_round(uint32_t *__restrict__ a0, uint32_t *__restrict__ a1,
                uint32_t *__restrict__ a2, uint32_t *__restrict__ a3,
                const uint32_t *__restrict__ rk)
{
    const uint32_t x0 = *a0, x1 = *a1, x2 = *a2, x3 = *a3;

    uint32_t t0 = rk[0], t1 = rk[1], t2 = rk[2], t3 = rk[3];

    t0 = AES32ESI(t0, x0, 0); t1 = AES32ESI(t1, x1, 0);
    t2 = AES32ESI(t2, x2, 0); t3 = AES32ESI(t3, x3, 0);

    t0 = AES32ESI(t0, x1, 1); t1 = AES32ESI(t1, x2, 1);
    t2 = AES32ESI(t2, x3, 1); t3 = AES32ESI(t3, x0, 1);

    t0 = AES32ESI(t0, x2, 2); t1 = AES32ESI(t1, x3, 2);
    t2 = AES32ESI(t2, x0, 2); t3 = AES32ESI(t3, x1, 2);

    t0 = AES32ESI(t0, x3, 3); t1 = AES32ESI(t1, x0, 3);
    t2 = AES32ESI(t2, x1, 3); t3 = AES32ESI(t3, x2, 3);

    *a0 = t0; *a1 = t1; *a2 = t2; *a3 = t3;
}

/* ---- Single-block encrypt -------------------------------------------- */

void aes128_encrypt_block_hardware(const uint8_t *__restrict__ plaintext,
                                   const uint32_t rk[__restrict__ 44],
                                   uint8_t *__restrict__ ciphertext)
{
    uint32_t a0 = load32_le(plaintext +  0) ^ rk[0];
    uint32_t a1 = load32_le(plaintext +  4) ^ rk[1];
    uint32_t a2 = load32_le(plaintext +  8) ^ rk[2];
    uint32_t a3 = load32_le(plaintext + 12) ^ rk[3];

#define MR(n) aes_round(&a0, &a1, &a2, &a3, rk + (n)*4)
    MR(1); MR(2); MR(3); MR(4); MR(5);
    MR(6); MR(7); MR(8); MR(9);
#undef MR

    aes_final_round(&a0, &a1, &a2, &a3, rk + 40);

    store32_le(ciphertext +  0, a0);
    store32_le(ciphertext +  4, a1);
    store32_le(ciphertext +  8, a2);
    store32_le(ciphertext + 12, a3);
}

/* ---- ECB encrypt (block-aligned) ------------------------------------- */

void aes128_ecb_encrypt(const uint8_t *__restrict__ plaintext, size_t len,
                        const uint8_t *__restrict__ key,
                        uint8_t *__restrict__ ciphertext)
{
    if (__builtin_expect((len & 15) != 0, 0))
        return;

    uint32_t rk[44];
    expand_key_u32(key, rk);

    const uint8_t *pt_end = plaintext + len;
    while (plaintext != pt_end) {
        aes128_encrypt_block_hardware(plaintext, rk, ciphertext);
        plaintext  += 16;
        ciphertext += 16;
    }
}

/* ---- Memory-mapped I/O helpers (logic preserved verbatim) ------------ */

void write_to_address(uintptr_t addr, uint32_t value)
{
    *(volatile uint32_t *)addr = value;
}

void write_v_to_address(uintptr_t addr, uint8_t vector[16])
{
    for (int i = 0; i < 4; i++) {
        uint32_t word;
        memcpy(&word, vector + i * 4, 4);
        write_to_address(addr + (uintptr_t)(i * 4), word);
    }
}

/* ---- Main verification (logic preserved verbatim) -------------------- */

int main(void)
{
    __attribute__((aligned(4))) uint8_t plaintext[16] = {
        'H','e','l','l','o',',',' ','W','o','r','l','d','!','0','0','0'
    };
    __attribute__((aligned(4))) uint8_t key[16] = {
        'c','e','s','e','4','0','4','0','p','a','s','s','w','o','r','d'
    };
    static const __attribute__((aligned(4))) uint8_t expected_output[16] = {
        0x14, 0x09, 0xA5, 0xFB, 0x1F, 0xF4, 0x4B, 0x71,
        0xBE, 0xAA, 0x25, 0x2E, 0x0F, 0x08, 0xF9, 0xAA
    };

    __attribute__((aligned(4))) uint8_t ciphertext[16] = {0};

    aes128_ecb_encrypt(plaintext, sizeof(plaintext), key, ciphertext);

    write_v_to_address(BASE_ADDR_DATA + 0x2030, (uint8_t *)expected_output);
    write_v_to_address(BASE_ADDR_DATA + 0x2040, ciphertext);

    uint32_t eq = 0;
    for (int i = 0; i < 4; i++) {
        uint32_t a, b;
        memcpy(&a, ciphertext      + i*4, 4);
        memcpy(&b, expected_output + i*4, 4);
        eq |= (a ^ b);
    }
    uint32_t result = (eq == 0) ? 0xCAFEBABE : 0xBAAAAAAD;

    write_to_address(BASE_ADDR_DATA + 0x2004, result);
    write_to_address(BASE_ADDR_DATA + 0x2000, 0xDEADBEEF);

    return 0;
}
