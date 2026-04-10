#include "SBox.h"
#include "GF256.h"
#include "word.h"
#include "../include/AES.h"
#ifndef CF_NO_TTABLES
#include "T_tables.h"
#endif
#include <stdio.h>
#include <stdlib.h>

/*
 * Pack column c of a row-major Block_t as a big-endian uint32_t
 * (row 0 = MSB).  The block stores word_[r] = row r, so column c
 * spans word_[0].uint08_[c] .. word_[3].uint08_[c].
 */
#ifndef CF_NO_TTABLES
static inline uint32_t block_col_be(const Block_t* b, size_t c) {
  return ((uint32_t)b->word_[0].uint08_[c] << 24)
       | ((uint32_t)b->word_[1].uint08_[c] << 16)
       | ((uint32_t)b->word_[2].uint08_[c] <<  8)
       |  (uint32_t)b->word_[3].uint08_[c];
}

/*
 * Apply InvMixColumns to a big-endian packed column word.
 * Used for decryption: the direct inverse cipher applies AddRoundKey
 * before InvMixColumns, so round keys must be pre-mixed via
 * InvMixColumns (linearity: InvMixColumns(s^k) = InvMixColumns(s)
 * ^ InvMixColumns(k)).
 */
static inline uint32_t inv_mix_col(uint32_t col) {
  uint8_t a = (col >> 24) & 0xffu;
  uint8_t b = (col >> 16) & 0xffu;
  uint8_t c = (col >>  8) & 0xffu;
  uint8_t d =  col        & 0xffu;
  return
    ((uint32_t)(multiply[0x0e][a]^multiply[0x0b][b]
               ^multiply[0x0d][c]^multiply[0x09][d]) << 24)
  | ((uint32_t)(multiply[0x09][a]^multiply[0x0e][b]
               ^multiply[0x0b][c]^multiply[0x0d][d]) << 16)
  | ((uint32_t)(multiply[0x0d][a]^multiply[0x09][b]
               ^multiply[0x0e][c]^multiply[0x0b][d]) <<  8)
  |  (uint32_t)(multiply[0x0b][a]^multiply[0x0d][b]
               ^multiply[0x09][c]^multiply[0x0e][d]);
}
#endif

static const Block_t a = {{                                                       // -For MixColumns.
  0x02, 0x03, 0x01, 0x01,
  0x01, 0x02, 0x03, 0x01,
  0x01, 0x01, 0x02, 0x03,
  0x03, 0x01, 0x01, 0x02
}};

static const Block_t aInv = {{                                                    // -For InvMixColumns.
  0x0E, 0x0B, 0x0D, 0x09,
  0x09, 0x0E, 0x0B, 0x0D,
  0x0D, 0x09, 0x0E, 0x0B,
  0x0B, 0x0D, 0x09, 0x0E
}};

static void copyBlock(const Block_t* source, Block_t* destination) {
  destination->uint64_[0] = source->uint64_[0];
  destination->uint64_[1] = source->uint64_[1];
}

static void XORblocks(const Block_t* b1, const Block_t* b2, Block_t* result) {
  result->uint64_[0] = b1->uint64_[0] ^ b2->uint64_[0];
  result->uint64_[1] = b1->uint64_[1] ^ b2->uint64_[1];
}

static void AddRoundKey(Block_t* b, const Block_t keyExpansion[], size_t round) {   // -Combines a round key with the state.
  XORblocks(b, keyExpansion+round, b);
}

static void SubBytes(Block_t* b) {                                                // -Applies a substitution table (S-box) to each uint8_t.
  SubWord(&b->word_[0]);
  SubWord(&b->word_[1]);
  SubWord(&b->word_[2]);
  SubWord(&b->word_[3]);
}

static void InvSubBytes(Block_t* b) {                                             // -Applies a substitution table (S-box) to each uint8_t.
  InvSubWord(&b->word_[0]);
  InvSubWord(&b->word_[1]);
  InvSubWord(&b->word_[2]);
  InvSubWord(&b->word_[3]);
}

static void ShiftRows(Block_t* b) {                                               // -Shift rows of the state array by different offset.
#if ENDIAN_UNKNOWN
  if(using_little_endian == -1)
    using_little_endian = usingLittleEndian();                                    // using_little_endian will determine the direction of the shift
#endif
  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[0];                                        // As a byte array, the rotation must be performed to the left, but since integer
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[1].uint32_ >>= 8;                             // types have endianess, the bit rotation must be performed according to it
  else b->word_[1].uint32_ <<= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[1].uint32_ >>= 8;
#else
  b->word_[1].uint32_ <<= 8;
#endif
  b->word_[1].uint08_[WORD_LASTIND] = temp1;

  // Shift of third row
  uint16_t temp2 = b->word_[2].uint16_[0];
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[2].uint32_ >>= 16;
  else b->word_[2].uint32_ <<= 16;
#elif IS_LITTLE_ENDIAN
  b->word_[2].uint32_ >>= 16;
#else
  b->word_[2].uint32_ <<= 16;
#endif
  b->word_[2].uint16_[WORD_LASTIND_SHORT] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[WORD_LASTIND];                             // Three shift to the left is equivalent to one shift to the right
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[3].uint32_ <<= 8;
  else b->word_[3].uint32_ >>= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[3].uint32_ <<= 8;
#else
  b->word_[3].uint32_ >>= 8;
#endif
  b->word_[3].uint08_[0] = temp3;
}

static void InvShiftRows(Block_t* b) {                                            // -Shift rows of the state array by different offset.
#if ENDIAN_UNKNOWN
  if(using_little_endian == -1)
    using_little_endian = usingLittleEndian();                                    // using_little_endian will determine the direction of the shift
#endif

  // Shift of second row
  uint8_t temp1 = b->word_[1].uint08_[WORD_LASTIND];                             // As a byte array, the rotation must be performed to the left, but since integer
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[1].uint32_ <<= 8;                             // types have endianess, the bit rotation must be performed according to it
  else b->word_[1].uint32_ >>= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[1].uint32_ <<= 8;
#else
  b->word_[1].uint32_ >>= 8;
#endif
  b->word_[1].uint08_[0] = temp1;

  // Shift of third row
  uint16_t temp2 = b->word_[2].uint16_[WORD_LASTIND_SHORT];
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[2].uint32_ <<= 16;
  else b->word_[2].uint32_ >>= 16;
#elif IS_LITTLE_ENDIAN
  b->word_[2].uint32_ <<= 16;
#else
  b->word_[2].uint32_ >>= 16;
#endif
  b->word_[2].uint16_[0] = temp2;

  // Shift of fourth row
  uint8_t temp3 = b->word_[3].uint08_[0];                                        // Three shift to the left is equivalent to one shift to the right
#if ENDIAN_UNKNOWN
  if(using_little_endian) b->word_[3].uint32_ >>= 8;
  else b->word_[3].uint32_ <<= 8;
#elif IS_LITTLE_ENDIAN
  b->word_[3].uint32_ >>= 8;
#else
  b->word_[3].uint32_ <<= 8;
#endif
  b->word_[3].uint08_[WORD_LASTIND] = temp3;
}

static void transposeBlock(const Block_t* source, Block_t* result){
  // Transposing and copying first column
  result->word_[0].uint08_[0] = source->word_[0].uint08_[0];
  result->word_[0].uint08_[1] = source->word_[1].uint08_[0];
  result->word_[0].uint08_[2] = source->word_[2].uint08_[0];
  result->word_[0].uint08_[3] = source->word_[3].uint08_[0];
  // Transposing and copying second column
  result->word_[1].uint08_[0] = source->word_[0].uint08_[1];
  result->word_[1].uint08_[1] = source->word_[1].uint08_[1];
  result->word_[1].uint08_[2] = source->word_[2].uint08_[1];
  result->word_[1].uint08_[3] = source->word_[3].uint08_[1];
  // Transposing and copying third column
  result->word_[2].uint08_[0] = source->word_[0].uint08_[2];
  result->word_[2].uint08_[1] = source->word_[1].uint08_[2];
  result->word_[2].uint08_[2] = source->word_[2].uint08_[2];
  result->word_[2].uint08_[3] = source->word_[3].uint08_[2];
  // Transposing and copying fourth column
  result->word_[3].uint08_[0] = source->word_[0].uint08_[3];
  result->word_[3].uint08_[1] = source->word_[1].uint08_[3];
  result->word_[3].uint08_[2] = source->word_[2].uint08_[3];
  result->word_[3].uint08_[3] = source->word_[3].uint08_[3];
}

static void MixColumns(Block_t* b) {                                              // -Mixes the data within each column of the state array.
  Block_t bT;
  transposeBlock(b,&bT);
  // First column
  b->uint08_[0] = dotProductWord(a.word_[0], bT.word_[0]);
  b->uint08_[4] = dotProductWord(a.word_[1], bT.word_[0]);
  b->uint08_[8] = dotProductWord(a.word_[2], bT.word_[0]);
  b->uint08_[12]= dotProductWord(a.word_[3], bT.word_[0]);
  // Second column
  b->uint08_[1] = dotProductWord(a.word_[0], bT.word_[1]);
  b->uint08_[5] = dotProductWord(a.word_[1], bT.word_[1]);
  b->uint08_[9] = dotProductWord(a.word_[2], bT.word_[1]);
  b->uint08_[13]= dotProductWord(a.word_[3], bT.word_[1]);
  // Third column
  b->uint08_[2] = dotProductWord(a.word_[0], bT.word_[2]);
  b->uint08_[6] = dotProductWord(a.word_[1], bT.word_[2]);
  b->uint08_[10]= dotProductWord(a.word_[2], bT.word_[2]);
  b->uint08_[14]= dotProductWord(a.word_[3], bT.word_[2]);
  // Fourth column
  b->uint08_[3] = dotProductWord(a.word_[0], bT.word_[3]);
  b->uint08_[7] = dotProductWord(a.word_[1], bT.word_[3]);
  b->uint08_[11]= dotProductWord(a.word_[2], bT.word_[3]);
  b->uint08_[15]= dotProductWord(a.word_[3], bT.word_[3]);
}

static void InvMixColumns(Block_t* b) {                                           // -Mixes the data within each column of the state array.
  Block_t bT;
  transposeBlock(b,&bT);
  // First column
  b->uint08_[0] = dotProductWord(aInv.word_[0], bT.word_[0]);
  b->uint08_[4] = dotProductWord(aInv.word_[1], bT.word_[0]);
  b->uint08_[8] = dotProductWord(aInv.word_[2], bT.word_[0]);
  b->uint08_[12]= dotProductWord(aInv.word_[3], bT.word_[0]);
  // Second column
  b->uint08_[1] = dotProductWord(aInv.word_[0], bT.word_[1]);
  b->uint08_[5] = dotProductWord(aInv.word_[1], bT.word_[1]);
  b->uint08_[9] = dotProductWord(aInv.word_[2], bT.word_[1]);
  b->uint08_[13]= dotProductWord(aInv.word_[3], bT.word_[1]);
  // Third column
  b->uint08_[2] = dotProductWord(aInv.word_[0], bT.word_[2]);
  b->uint08_[6] = dotProductWord(aInv.word_[1], bT.word_[2]);
  b->uint08_[10]= dotProductWord(aInv.word_[2], bT.word_[2]);
  b->uint08_[14]= dotProductWord(aInv.word_[3], bT.word_[2]);
  // Fourth column
  b->uint08_[3] = dotProductWord(aInv.word_[0], bT.word_[3]);
  b->uint08_[7] = dotProductWord(aInv.word_[1], bT.word_[3]);
  b->uint08_[11]= dotProductWord(aInv.word_[2], bT.word_[3]);
  b->uint08_[15]= dotProductWord(aInv.word_[3], bT.word_[3]);
}

enum ExceptionCode encryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug) {
  size_t i, j;
  // -Debugging purposes. Columns of the debugging table.
  Block_t* SOR;                                                                   // Start of round
  Block_t* ASB;                                                                   // After SubBytes
  Block_t* ASR;                                                                   // After ShiftRows
  Block_t *AMC;                                                                   // After MixColumns
  SOR = ASB = ASR = AMC = NULL;

  if(debug) {
    SOR = (Block_t*)malloc((ke_p->Nr+2)*sizeof(Block_t));
    AMC = (Block_t*)malloc((ke_p->Nr - 1)*sizeof(Block_t));
    ASB = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
    ASR = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
  }

  if(input == NULL) return NullInput;
  if(output== NULL) return NullOutput;

#ifndef CF_NO_TTABLES
  if (!debug) {
    if(ke_p == NULL) return NullKeyExpansion;
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    size_t r;

    /* Load state as column-major big-endian uint32_t */
    s0 = block_col_be(input, 0);
    s1 = block_col_be(input, 1);
    s2 = block_col_be(input, 2);
    s3 = block_col_be(input, 3);

    /* AddRoundKey round 0 */
    s0 ^= block_col_be(&ke_p->dataBlocks[0], 0);
    s1 ^= block_col_be(&ke_p->dataBlocks[0], 1);
    s2 ^= block_col_be(&ke_p->dataBlocks[0], 2);
    s3 ^= block_col_be(&ke_p->dataBlocks[0], 3);

    /* Rounds 1 ... Nr-1 */
    for (r = 1; r < ke_p->Nr; r++) {
      t0 = Te0[ s0 >> 24         ]
         ^ Te1[(s1 >> 16) & 0xffu]
         ^ Te2[(s2 >>  8) & 0xffu]
         ^ Te3[ s3        & 0xffu]
         ^ block_col_be(&ke_p->dataBlocks[r], 0);
      t1 = Te0[ s1 >> 24         ]
         ^ Te1[(s2 >> 16) & 0xffu]
         ^ Te2[(s3 >>  8) & 0xffu]
         ^ Te3[ s0        & 0xffu]
         ^ block_col_be(&ke_p->dataBlocks[r], 1);
      t2 = Te0[ s2 >> 24         ]
         ^ Te1[(s3 >> 16) & 0xffu]
         ^ Te2[(s0 >>  8) & 0xffu]
         ^ Te3[ s1        & 0xffu]
         ^ block_col_be(&ke_p->dataBlocks[r], 2);
      t3 = Te0[ s3 >> 24         ]
         ^ Te1[(s0 >> 16) & 0xffu]
         ^ Te2[(s1 >>  8) & 0xffu]
         ^ Te3[ s2        & 0xffu]
         ^ block_col_be(&ke_p->dataBlocks[r], 3);
      s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* Final round — SubBytes + ShiftRows + AddRoundKey, no MixColumns */
    t0 = (Te4[ s0 >> 24         ] & 0xff000000u)
       ^ (Te4[(s1 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Te4[(s2 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Te4[ s3        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[r], 0);
    t1 = (Te4[ s1 >> 24         ] & 0xff000000u)
       ^ (Te4[(s2 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Te4[(s3 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Te4[ s0        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[r], 1);
    t2 = (Te4[ s2 >> 24         ] & 0xff000000u)
       ^ (Te4[(s3 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Te4[(s0 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Te4[ s1        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[r], 2);
    t3 = (Te4[ s3 >> 24         ] & 0xff000000u)
       ^ (Te4[(s0 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Te4[(s1 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Te4[ s2        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[r], 3);

    /* Write back: t0-t3 are output columns; convert to row-major */
    output->word_[0].uint08_[0] = (t0 >> 24) & 0xffu;
    output->word_[0].uint08_[1] = (t1 >> 24) & 0xffu;
    output->word_[0].uint08_[2] = (t2 >> 24) & 0xffu;
    output->word_[0].uint08_[3] = (t3 >> 24) & 0xffu;
    output->word_[1].uint08_[0] = (t0 >> 16) & 0xffu;
    output->word_[1].uint08_[1] = (t1 >> 16) & 0xffu;
    output->word_[1].uint08_[2] = (t2 >> 16) & 0xffu;
    output->word_[1].uint08_[3] = (t3 >> 16) & 0xffu;
    output->word_[2].uint08_[0] = (t0 >>  8) & 0xffu;
    output->word_[2].uint08_[1] = (t1 >>  8) & 0xffu;
    output->word_[2].uint08_[2] = (t2 >>  8) & 0xffu;
    output->word_[2].uint08_[3] = (t3 >>  8) & 0xffu;
    output->word_[3].uint08_[0] =  t0        & 0xffu;
    output->word_[3].uint08_[1] =  t1        & 0xffu;
    output->word_[3].uint08_[2] =  t2        & 0xffu;
    output->word_[3].uint08_[3] =  t3        & 0xffu;

    return NoException;
  }
#endif /* CF_NO_TTABLES */

  if(input != output) copyBlock(input, output);

  if(debug) copyBlock(output,SOR);                                              // Equivalent to copyBlock(output,&SOR[0])

  if(ke_p == NULL) return NullKeyExpansion;
  AddRoundKey(output, ke_p->dataBlocks, 0);
  if(debug) copyBlock(output,SOR + 1);                                          // Equivalent to copyBlock(output,&SOR[1])
  for(i = 1; i < ke_p->Nr; i++) {
    SubBytes(output);
    if(debug) copyBlock(output, ASB + (i-1));
    ShiftRows(output);
    if(debug) copyBlock(output, ASR + (i-1));
    MixColumns(output);
    if(debug) copyBlock(output, AMC + (i-1));
    AddRoundKey(output, ke_p->dataBlocks, i);
    if(debug) copyBlock(output, SOR + (i+1));
  }
  SubBytes(output);
  if(debug) copyBlock(output, ASB + (i-1));
  ShiftRows(output);
  if(debug) copyBlock(output, ASR + (i-1));
  AddRoundKey(output, ke_p->dataBlocks, i);
  if(debug) copyBlock(output, SOR + (i-1));

  if(debug) {
    printf(
      "------------------------------------ Cipher. Nk = %d ------------------------------------\n"
      "----------------------------------------------------------------------------------------\n"
      " Round   |    Start of   |     After     |     After     |     After     |   Round key  \n"
      " Number  |     round     |    SubBytes   |   ShiftRows   |   MixColumns  |    value     \n"
      "         |               |               |               |               |              \n"
      "----------------------------------------------------------------------------------------\n",
      ke_p->Nk
    );

    for(i = 0; i < 4; i++) {
      if(i == 1) printf(" input  ");
      else printf("        ");
      printf(" | ");
      printWord(SOR[0].word_[i]);
      printf(" |               |               |               | ");
      printWord(ke_p->dataBlocks[0].word_[i]);
      printf("\n");
    }
    printf("\n");

    for(i = 1; i <= ke_p->Nr; i++) {
      for(j = 0; j < NB; j++) {
        if(j == 1) {
          printf("    ");
          if(i < 10) printf("%lu   ", i);
          else printf("%lu  ", i);
        }
        else printf("        ");
        printf(" | ");
        printWord(SOR[i].word_[j]);
        printf(" | ");
        printWord(ASB[i-1].word_[j]);
        printf(" | ");
        printWord(ASR[i-1].word_[j]);
        printf(" | ");
        if(i < ke_p->Nr) printWord(AMC[i-1].word_[j]);
        else printf("             ");
        printf(" | ");
        printWord(ke_p->dataBlocks[i].word_[j]);
        printf("\n");
      }
      printf(
        "----------------------------------------------------------------------------------------\n"
      );
    }
    for(i = 0; i < 4; i++) {
      if(i == 1) printf(" output ");
      else printf("        ");
      printf(" | ");
      printWord(output->word_[i]);
      printf(" |               |               |               |               \n");
    }
    printf(
      "----------------------------------------------------------------------------------------\n"
    );
    debug = false;
  }
  if(SOR != NULL) { free(SOR); SOR=NULL; }
  if(ASB != NULL) { free(ASB); ASB=NULL; }
  if(ASR != NULL) { free(ASR); ASR=NULL; }
  if(AMC != NULL) { free(AMC); AMC=NULL; }

  return NoException;
}

enum ExceptionCode decryptBlock(const Block_t* input, const KeyExpansion_t* ke_p, Block_t* output, bool debug) {
  size_t i, j;
  // -Debugging purposes. Columns of the debugging table.
  Block_t* SOR;                                                                   // Start of round
  Block_t* AiSB;                                                                  // After SubBytes
  Block_t* AiSR;                                                                  // After ShiftRows
  Block_t* AARK;                                                                  // After MixColumns
  SOR = AiSB = AiSR = AARK = NULL;

  if(debug) {
    SOR = (Block_t*)malloc((ke_p->Nr+1)*sizeof(Block_t));
    AARK = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
    AiSB = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
    AiSR = (Block_t*)malloc(ke_p->Nr*sizeof(Block_t));
  }

  if(input == NULL) return NullInput;
  if(output== NULL) return NullOutput;

#ifndef CF_NO_TTABLES
  if (!debug) {
    if(ke_p == NULL) return NullKeyExpansion;
    uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
    size_t r;

    /* Load state as column-major big-endian uint32_t */
    s0 = block_col_be(input, 0);
    s1 = block_col_be(input, 1);
    s2 = block_col_be(input, 2);
    s3 = block_col_be(input, 3);

    /* AddRoundKey round Nr */
    s0 ^= block_col_be(&ke_p->dataBlocks[ke_p->Nr], 0);
    s1 ^= block_col_be(&ke_p->dataBlocks[ke_p->Nr], 1);
    s2 ^= block_col_be(&ke_p->dataBlocks[ke_p->Nr], 2);
    s3 ^= block_col_be(&ke_p->dataBlocks[ke_p->Nr], 3);

    /* Rounds Nr-1 ... 1
     * T-tables fuse InvShiftRows + InvSubBytes + InvMixColumns.
     * Original cipher order: InvShiftRows → InvSubBytes → AddRoundKey
     * → InvMixColumns.  By linearity of InvMixColumns:
     *   InvMixColumns(s ^ rk) = InvMixColumns(s) ^ InvMixColumns(rk)
     * so the round key is pre-mixed with inv_mix_col(). */
    for (r = ke_p->Nr - 1; r > 0; r--) {
      t0 = Td0[ s0 >> 24         ]
         ^ Td1[(s3 >> 16) & 0xffu]
         ^ Td2[(s2 >>  8) & 0xffu]
         ^ Td3[ s1        & 0xffu]
         ^ ke_p->invRoundCols[r * 4 + 0];
      t1 = Td0[ s1 >> 24         ]
         ^ Td1[(s0 >> 16) & 0xffu]
         ^ Td2[(s3 >>  8) & 0xffu]
         ^ Td3[ s2        & 0xffu]
         ^ ke_p->invRoundCols[r * 4 + 1];
      t2 = Td0[ s2 >> 24         ]
         ^ Td1[(s1 >> 16) & 0xffu]
         ^ Td2[(s0 >>  8) & 0xffu]
         ^ Td3[ s3        & 0xffu]
         ^ ke_p->invRoundCols[r * 4 + 2];
      t3 = Td0[ s3 >> 24         ]
         ^ Td1[(s2 >> 16) & 0xffu]
         ^ Td2[(s1 >>  8) & 0xffu]
         ^ Td3[ s0        & 0xffu]
         ^ ke_p->invRoundCols[r * 4 + 3];
      s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    /* Final round — InvSubBytes + InvShiftRows + AddRoundKey,
     * no InvMixColumns */
    t0 = (Td4[ s0 >> 24         ] & 0xff000000u)
       ^ (Td4[(s3 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Td4[(s2 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Td4[ s1        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[0], 0);
    t1 = (Td4[ s1 >> 24         ] & 0xff000000u)
       ^ (Td4[(s0 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Td4[(s3 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Td4[ s2        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[0], 1);
    t2 = (Td4[ s2 >> 24         ] & 0xff000000u)
       ^ (Td4[(s1 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Td4[(s0 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Td4[ s3        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[0], 2);
    t3 = (Td4[ s3 >> 24         ] & 0xff000000u)
       ^ (Td4[(s2 >> 16) & 0xffu] & 0x00ff0000u)
       ^ (Td4[(s1 >>  8) & 0xffu] & 0x0000ff00u)
       ^ (Td4[ s0        & 0xffu] & 0x000000ffu)
       ^ block_col_be(&ke_p->dataBlocks[0], 3);

    /* Write back: t0-t3 are output columns; convert to row-major */
    output->word_[0].uint08_[0] = (t0 >> 24) & 0xffu;
    output->word_[0].uint08_[1] = (t1 >> 24) & 0xffu;
    output->word_[0].uint08_[2] = (t2 >> 24) & 0xffu;
    output->word_[0].uint08_[3] = (t3 >> 24) & 0xffu;
    output->word_[1].uint08_[0] = (t0 >> 16) & 0xffu;
    output->word_[1].uint08_[1] = (t1 >> 16) & 0xffu;
    output->word_[1].uint08_[2] = (t2 >> 16) & 0xffu;
    output->word_[1].uint08_[3] = (t3 >> 16) & 0xffu;
    output->word_[2].uint08_[0] = (t0 >>  8) & 0xffu;
    output->word_[2].uint08_[1] = (t1 >>  8) & 0xffu;
    output->word_[2].uint08_[2] = (t2 >>  8) & 0xffu;
    output->word_[2].uint08_[3] = (t3 >>  8) & 0xffu;
    output->word_[3].uint08_[0] =  t0        & 0xffu;
    output->word_[3].uint08_[1] =  t1        & 0xffu;
    output->word_[3].uint08_[2] =  t2        & 0xffu;
    output->word_[3].uint08_[3] =  t3        & 0xffu;

    return NoException;
  }
#endif /* CF_NO_TTABLES */

  if(input != output) copyBlock(input, output);

  if(debug) copyBlock(output,SOR + ke_p->Nr);                                   // Equivalent to copyBlock(output,&SOR[ke_p->Nr])

  if(ke_p == NULL) return NullKeyExpansion;
  AddRoundKey(output, ke_p->dataBlocks, ke_p->Nr);
  if(debug) copyBlock(output,SOR + ke_p->Nr-1);                                 // Equivalent to copyBlock(output,&SOR[ke_p->Nr])

  for(i = ke_p->Nr - 1; i > 0; i--) {
    InvShiftRows(output);
    if(debug) copyBlock(output, AiSR + i);
    InvSubBytes(output);
    if(debug) copyBlock(output, AiSB + i);
    AddRoundKey(output, ke_p->dataBlocks, i);
    if(debug) copyBlock(output, AARK + i);
    InvMixColumns(output);
    if(debug) copyBlock(output, SOR + (i-1));
  }
  InvShiftRows(output);
  if(debug) copyBlock(output, AiSR);
  InvSubBytes(output);
  if(debug) copyBlock(output, AiSB);
  AddRoundKey(output, ke_p->dataBlocks, 0);
  if(debug) copyBlock(output, AARK);

  if(debug) {
    printf(
      "---------------------------------- Decipher. Nk = %d ------------------------------------\n"
      "----------------------------------------------------------------------------------------\n"
      " Round   |    Start of   |     After     |     After     |     After     |   Round key  \n"
      " Number  |     round     |  InvShiftRows |  InvSubBytes  |  AddRoundKey  |    value     \n"
      "         |               |               |               |               |              \n"
      "----------------------------------------------------------------------------------------\n",
      ke_p->Nk
    );

    for(i = 0; i < NB; i++) {
      if(i == 1) printf(" input  ");
      else printf("        ");
      printf(" | ");
      printWord(SOR[ke_p->Nr].word_[i]);
      printf(" |               |               |               | ");
      printWord(ke_p->dataBlocks[0].word_[i]);
      printf("\n");
    }
    printf("\n");

    for(i = ke_p->Nr-1; i != (size_t)-1 ; i--) {
      for(j = 0; j < NB; j++) {
        if(j == 1) {
          printf("    ");
          if(i < 10) printf("%lu   ", i);
          else printf("%lu  ", i);
        }
        else printf("        ");
        printf(" | ");
        printWord(SOR[i].word_[j]);
        printf(" | ");
        printWord(AiSR[i].word_[j]);
        printf(" | ");
        printWord(AiSB[i].word_[j]);
        printf(" | ");
        printWord(AARK[i].word_[j]);
        printf(" | ");
        printWord(ke_p->dataBlocks[i].word_[j]);
        printf("\n");
      }
      printf(
        "----------------------------------------------------------------------------------------\n"
      );
    }
    for(i = 0; i < 4; i++) {
      if(i == 1) printf(" output ");
      else printf("        ");
      printf(" | ");
      printWord(output->word_[i]);
      printf(" |               |               |               |               \n");
    }
    printf(
      "----------------------------------------------------------------------------------------\n"
    );
    debug = false;
  }
  if(SOR != NULL) { free(SOR); SOR=NULL; }
  if(AiSB != NULL) { free(AiSB); AiSB=NULL; }
  if(AiSR != NULL) { free(AiSR); AiSR=NULL; }
  if(AARK != NULL) { free(AARK); AARK=NULL; }

  return NoException;
}
