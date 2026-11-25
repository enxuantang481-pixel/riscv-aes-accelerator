#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BASE_ADDR_DATA 0x42000000
#define BASE_ADDR_END (BASE_ADDR_DATA + 0x2000)

static inline uint32_t load32_le(const uint8_t *p) {
  uint32_t v;
  memcpy(&v, p, 4);
  return v;
}

static __attribute__((always_inline)) inline void store32_le(uint8_t *p,
                                                             uint32_t v) {
  memcpy(p, &v, 4);
}

#define AES32ESMI(rs1, rs2, bs)                                                \
  ({                                                                           \
    uint32_t _rd;                                                              \
    __asm__ volatile(".insn r 0x33, 0x0, ((0x13) | (" #bs                      \
                     " << 5)), %0, %1, %2"                                     \
                     : "=r"(_rd)                                               \
                     : "r"(rs1), "r"(rs2));                                    \
    _rd;                                                                       \
  })

#define AES32ESI(rs1, rs2, bs)                                                 \
  ({                                                                           \
    uint32_t _rd;                                                              \
    __asm__ volatile(".insn r 0x33, 0x0, ((0x11) | (" #bs                      \
                     " << 5)), %0, %1, %2"                                     \
                     : "=r"(_rd)                                               \
                     : "r"(rs1), "r"(rs2));                                    \
    _rd;                                                                       \
  })

#define AES32KS1I(rs1, rnum)                                                   \
  ({                                                                           \
    uint32_t _rd;                                                              \
    __asm__ volatile(".insn r 0x33, 0x0, 0x18, %0, %1, x" #rnum                \
                     : "=r"(_rd)                                               \
                     : "r"(rs1));                                              \
    _rd;                                                                       \
  })

#define AES32KS2(rs1, rs2)                                                     \
  ({                                                                           \
    uint32_t _rd;                                                              \
    __asm__ volatile(".insn r 0x33, 0x0, 0x19, %0, %1, %2"                     \
                     : "=r"(_rd)                                               \
                     : "r"(rs1), "r"(rs2));                                    \
    _rd;                                                                       \
  })

void expand_key_u32(const uint8_t *restrict key, uint32_t rk[restrict 44]) {
  rk[0] = load32_le(key + 0);
  rk[1] = load32_le(key + 4);
  rk[2] = load32_le(key + 8);
  rk[3] = load32_le(key + 12);

  // Round 1 (rnum=0)
  uint32_t tmp;
  tmp = AES32KS1I(rk[3], 0);
  rk[4] = AES32KS2(rk[0], tmp);
  rk[5] = AES32KS2(rk[1], rk[4]);
  rk[6] = AES32KS2(rk[2], rk[5]);
  rk[7] = AES32KS2(rk[3], rk[6]);

  // Round 2 (rnum=1)
  tmp = AES32KS1I(rk[7], 1);
  rk[8] = AES32KS2(rk[4], tmp);
  rk[9] = AES32KS2(rk[5], rk[8]);
  rk[10] = AES32KS2(rk[6], rk[9]);
  rk[11] = AES32KS2(rk[7], rk[10]);

  // Round 3 (rnum=2)
  tmp = AES32KS1I(rk[11], 2);
  rk[12] = AES32KS2(rk[8], tmp);
  rk[13] = AES32KS2(rk[9], rk[12]);
  rk[14] = AES32KS2(rk[10], rk[13]);
  rk[15] = AES32KS2(rk[11], rk[14]);

  // Round 4 (rnum=3)
  tmp = AES32KS1I(rk[15], 3);
  rk[16] = AES32KS2(rk[12], tmp);
  rk[17] = AES32KS2(rk[13], rk[16]);
  rk[18] = AES32KS2(rk[14], rk[17]);
  rk[19] = AES32KS2(rk[15], rk[18]);

  // Round 5 (rnum=4)
  tmp = AES32KS1I(rk[19], 4);
  rk[20] = AES32KS2(rk[16], tmp);
  rk[21] = AES32KS2(rk[17], rk[20]);
  rk[22] = AES32KS2(rk[18], rk[21]);
  rk[23] = AES32KS2(rk[19], rk[22]);

  // Round 6 (rnum=5)
  tmp = AES32KS1I(rk[23], 5);
  rk[24] = AES32KS2(rk[20], tmp);
  rk[25] = AES32KS2(rk[21], rk[24]);
  rk[26] = AES32KS2(rk[22], rk[25]);
  rk[27] = AES32KS2(rk[23], rk[26]);

  // Round 7 (rnum=6)
  tmp = AES32KS1I(rk[27], 6);
  rk[28] = AES32KS2(rk[24], tmp);
  rk[29] = AES32KS2(rk[25], rk[28]);
  rk[30] = AES32KS2(rk[26], rk[29]);
  rk[31] = AES32KS2(rk[27], rk[30]);

  // Round 8 (rnum=7)
  tmp = AES32KS1I(rk[31], 7);
  rk[32] = AES32KS2(rk[28], tmp);
  rk[33] = AES32KS2(rk[29], rk[32]);
  rk[34] = AES32KS2(rk[30], rk[33]);
  rk[35] = AES32KS2(rk[31], rk[34]);

  // Round 9 (rnum=8)
  tmp = AES32KS1I(rk[35], 8);
  rk[36] = AES32KS2(rk[32], tmp);
  rk[37] = AES32KS2(rk[33], rk[36]);
  rk[38] = AES32KS2(rk[34], rk[37]);
  rk[39] = AES32KS2(rk[35], rk[38]);

  // Round 10 (rnum=9)
  tmp = AES32KS1I(rk[39], 9);
  rk[40] = AES32KS2(rk[36], tmp);
  rk[41] = AES32KS2(rk[37], rk[40]);
  rk[42] = AES32KS2(rk[38], rk[41]);
  rk[43] = AES32KS2(rk[39], rk[42]);

  *(volatile uint32_t *)(0x42002008) = 0xAAAAAAAA;
}

static __attribute__((always_inline)) inline void
aes_round(uint32_t *a0, uint32_t *a1, uint32_t *a2, uint32_t *a3,
          const uint32_t *restrict rk) {
  uint32_t x0 = *a0;
  uint32_t x1 = *a1;
  uint32_t x2 = *a2;
  uint32_t x3 = *a3;

  uint32_t t0 = AES32ESMI(rk[0], x0, 0);
  t0 = AES32ESMI(t0, x1, 1);
  t0 = AES32ESMI(t0, x2, 2);
  t0 = AES32ESMI(t0, x3, 3);

  uint32_t t1 = AES32ESMI(rk[1], x1, 0);
  t1 = AES32ESMI(t1, x2, 1);
  t1 = AES32ESMI(t1, x3, 2);
  t1 = AES32ESMI(t1, x0, 3);

  uint32_t t2 = AES32ESMI(rk[2], x2, 0);
  t2 = AES32ESMI(t2, x3, 1);
  t2 = AES32ESMI(t2, x0, 2);
  t2 = AES32ESMI(t2, x1, 3);

  uint32_t t3 = AES32ESMI(rk[3], x3, 0);
  t3 = AES32ESMI(t3, x0, 1);
  t3 = AES32ESMI(t3, x1, 2);
  t3 = AES32ESMI(t3, x2, 3);

  *a0 = t0;
  *a1 = t1;
  *a2 = t2;
  *a3 = t3;
}

static __attribute__((always_inline)) inline void
aes_final_round(uint32_t *a0, uint32_t *a1, uint32_t *a2, uint32_t *a3,
                const uint32_t *restrict rk) {
  uint32_t x0 = *a0;
  uint32_t x1 = *a1;
  uint32_t x2 = *a2;
  uint32_t x3 = *a3;

  uint32_t t0 = AES32ESI(rk[0], x0, 0);
  t0 = AES32ESI(t0, x1, 1);
  t0 = AES32ESI(t0, x2, 2);
  t0 = AES32ESI(t0, x3, 3);

  uint32_t t1 = AES32ESI(rk[1], x1, 0);
  t1 = AES32ESI(t1, x2, 1);
  t1 = AES32ESI(t1, x3, 2);
  t1 = AES32ESI(t1, x0, 3);

  uint32_t t2 = AES32ESI(rk[2], x2, 0);
  t2 = AES32ESI(t2, x3, 1);
  t2 = AES32ESI(t2, x0, 2);
  t2 = AES32ESI(t2, x1, 3);

  uint32_t t3 = AES32ESI(rk[3], x3, 0);
  t3 = AES32ESI(t3, x0, 1);
  t3 = AES32ESI(t3, x1, 2);
  t3 = AES32ESI(t3, x2, 3);

  *a0 = t0;
  *a1 = t1;
  *a2 = t2;
  *a3 = t3;
}

void aes128_encrypt_block_hardware(const uint8_t *restrict plaintext,
                                   const uint32_t rk[restrict 44],
                                   uint8_t *restrict ciphertext) {
  uint32_t a0 = load32_le(plaintext + 0) ^ rk[0];
  uint32_t a1 = load32_le(plaintext + 4) ^ rk[1];
  uint32_t a2 = load32_le(plaintext + 8) ^ rk[2];
  uint32_t a3 = load32_le(plaintext + 12) ^ rk[3];

#pragma GCC unroll 9
  for (int round = 1; round < 10; round++) {
    aes_round(&a0, &a1, &a2, &a3, rk + round * 4);
  }

  aes_final_round(&a0, &a1, &a2, &a3, rk + 40);

  store32_le(ciphertext + 0, a0);
  store32_le(ciphertext + 4, a1);
  store32_le(ciphertext + 8, a2);
  store32_le(ciphertext + 12, a3);
}

void aes128_ecb_encrypt(const uint8_t *restrict plaintext, size_t len,
                        const uint8_t *restrict key,
                        uint8_t *restrict ciphertext) {
  if ((len & 15) != 0) {
    return;
  }

  uint32_t rk[44];
  expand_key_u32(key, rk);

#pragma GCC unroll 4
  for (size_t i = 0; i < len; i += 16) {
    aes128_encrypt_block_hardware(plaintext + i, rk, ciphertext + i);
  }
}

// Memory mapping tracking utilities (Left completely untouched)
void write_to_address(uintptr_t addr, uint32_t value) {
  *(volatile uint32_t *)addr = value;
}

void write_v_to_address(uintptr_t addr, uint8_t vector[16]) {
  uint32_t *vector_word = (uint32_t *)vector;

#pragma GCC unroll 3
  for (int i = 0; i < 4; i++) {
    write_to_address(addr + i * 0x4, vector_word[i]);
  }
}

// Main verification module container (Left completely untouched)
int main() {
  uint8_t plaintext[16] = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W',
                           'o', 'r', 'l', 'd', '!', '0', '0', '0'};
  uint8_t key[16] = {'c', 'e', 's', 'e', '4', '0', '4', '0',
                     'p', 'a', 's', 's', 'w', 'o', 'r', 'd'};
  uint8_t expected_output[16] = {0x14, 0x09, 0xA5, 0xFB, 0x1F, 0xF4,
                                 0x4B, 0x71, 0xBE, 0xAA, 0x25, 0x2E,
                                 0x0F, 0x08, 0xF9, 0xAA};
  uint8_t ciphertext[16] = {0};
  size_t len = 16;

  uintptr_t addr;
  uint32_t value;

  aes128_ecb_encrypt(plaintext, len, key, ciphertext);

  // Write expected
  addr = BASE_ADDR_DATA + 0x2030;
  write_v_to_address(addr, expected_output);

  // Write ciphertext via aligned buffer ONLY
  __attribute__((aligned(4))) uint8_t aligned_cipher[16];
  memcpy(aligned_cipher, ciphertext, 16);
  addr = BASE_ADDR_DATA + 0x2040;
  write_v_to_address(addr, aligned_cipher); // only one write here

  addr = BASE_ADDR_DATA + 0x2004;
  value = 0xCAFEBABE;

#pragma GCC unroll 15
  for (int i = 0; i < 16; i++) {
    if (ciphertext[i] != expected_output[i]) {
      value = 0xBAAAAAAD;
      break;
    }
  }

  write_to_address(addr, value);

  addr = BASE_ADDR_DATA + 0x2000;
  write_to_address(addr, 0xDEADBEEF);

  return 0;
}
