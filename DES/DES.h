/*
DES Assignment

DES Algorithm is a Feistel cipher with the following numerology:

o 16 rounds
o 64-bit block length
o 56-bit key
o 48-bit subkeys

with a function f that can be written as:
F( R(i-1) , K(i) ) = P-box{ S-boxes[ Expand( R(i-1) ) XOR K(i) ] }
Using CBC with an Initializing Vector IV
*/
#ifndef DES_H
#define DES_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <time.h>

#define ENCODE 1
#define DECODE 0
#define ACTION_ENCRYPT "-enc"
#define ACTION_DECRYPT "-dec"
#define BLOCK_SIZE 64
#define KEY_SIZE 64
#define PC1_SIZE 56
#define PC2_SIZE 48
#define E_SIZE 48
#define P_SIZE 32
#define S_SIZE 64
#define KEY_ROUNDS 16
#define BYTE_SIZE 8

// Help print in binary per nibble (4 bits)
#define BYTETOBINARYPATTER "%d%d%d%d"
#define BYTETOBINARY(nibble)  \
  (nibble & 0x8 ? 1 : 0), \
  (nibble & 0x4 ? 1 : 0), \
  (nibble & 0x2 ? 1 : 0), \
  (nibble & 0x1 ? 1 : 0)

// all tables turned into int arrays to help reduce function calls
// by creating one universal permute function
extern int IP[64];
extern int FP[64];
extern int PC1[56];
extern int PC2[48];
extern int E[48];
extern int P[32];
extern int S1[64];
extern int S2[64];
extern int S3[64];
extern int S4[64];
extern int S5[64];
extern int S6[64];
extern int S7[64];
extern int S8[64];
extern int* SBOXMAP[8];

// int can at times not be 32bits, uint32_t will help deal with that
// and avoid confusing an F with a negative decimal
typedef struct{
   uint32_t l;
   uint32_t r;
} key_block;

void print_b(key_block, int);
void encrypt(FILE*,FILE*,key_block*,key_block);
void decrypt(FILE*,FILE*,key_block*,key_block);
key_block* generate_key_schedule(key_block);

#endif
