#include "DES.h"

//*******************************************
//PRINT BINARY
//*******************************************
// print a block as binary per nibble (4bits at a time)
void print_b(key_block block, int nibbles){
   int i;
   uint32_t left = block.l;
   uint32_t right = block.r;
   uint8_t nibble;
   printf("\n0b");
   for(i = nibbles - 1; i >= 0; i--){
      nibble = left >> (4 * i);
      printf(""BYTETOBINARYPATTER, BYTETOBINARY(nibble));
   }
   printf("\n  ");
   for(i = nibbles - 1; i >= 0; i--){
      nibble = right >> (4 * i);
      printf(""BYTETOBINARYPATTER, BYTETOBINARY(nibble));
   }
   puts("\n");
}
//*******************************************
//PERMUTE
//*******************************************
// permute key or block according to given table values and passing
// their respective sizes for control
// It will do this by shifting the bit it wants all the way to the right
// mask all other bits and then shift it to the position it should be in
// as the permutation asks, taht being the first bit taken be the first
// bit filling key block result from left to right
key_block permute(key_block key, int* table, int key_len, int table_len){
   int i;
   key_block result,temp;
   result.l = 0;
   result.r = 0;

   for(i = 0; i < table_len; i++){
      // for the first half of the table, insert bits into left halve
      // then for the second half, insert bits into right halve
      if(i < table_len/2){

         // get bit from the left half of the block if bit location is less
         // than half the length of the block, else get it from the right
         if(table[i] <= key_len/2)
            result.l |= ((key.l >> (key_len/2-table[i])) & 0x01) << ((table_len/2 - 1) - i);
         else
            result.l |= ((key.r >> (key_len/2-(table[i] - key_len/2))) & 0x01) << ((table_len/2 - 1) - i);
      }
      else{
         if(table[i] <= key_len/2)
            result.r |= ((key.l >> (key_len/2-table[i])) & 0x01) << ((table_len/2 - 1) - (i - table_len/2));
         else
            result.r |= ((key.r >> (key_len/2-(table[i] - key_len/2))) & 0x01) << ((table_len/2 - 1) - (i - table_len/2));
      }
   }

   return result;
}
//*******************************************
//SHIFT SUBKEYS
//*******************************************
// create 16 subkeys doing bit rotation according to shift_schedule
// shift schedule determines how many times to shift bits left
// and then use the left most "lost" bit the new right most bit
// for next subkey to continue on all 16 subkeys
key_block* shift_subkeys(key_block permuted){
   int i, j;
   uint32_t top_bit_l, top_bit_r;
   uint32_t shift_schedule[KEY_ROUNDS] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
   key_block* shifted_subkeys = (key_block*)malloc(sizeof(key_block) * KEY_ROUNDS);

   top_bit_l = (permuted.l & 0x8000000) >> 27;
   top_bit_r = (permuted.r & 0x8000000) >> 27;

   shifted_subkeys[0].l = ((permuted.l << 1) | top_bit_l) & 0x0FFFFFFF;
   shifted_subkeys[0].r = ((permuted.r << 1) | top_bit_r) & 0x0FFFFFFF;

   for(i = 1; i < KEY_ROUNDS; i++){
      shifted_subkeys[i].l = shifted_subkeys[i - 1].l;
      shifted_subkeys[i].r = shifted_subkeys[i - 1].r;

      for(j = 0; j < shift_schedule[i]; j++){
         top_bit_l = (shifted_subkeys[i].l & 0x8000000) >> 27;
         top_bit_r = (shifted_subkeys[i].r & 0x8000000) >> 27;
         shifted_subkeys[i].l = ((shifted_subkeys[i].l << 1) | top_bit_l) & 0x0FFFFFFF;
         shifted_subkeys[i].r = ((shifted_subkeys[i].r << 1) | top_bit_r) & 0x0FFFFFFF;
      }
   }

   return shifted_subkeys;
}
//*******************************************
//GENERATE KEY SCHEDULE
//*******************************************
// process to generate 16 48bit keys
// prints are used for testing purposes using information in 
// http://page.math.tu-berlin.re/~kant/teaching/hess/krypto-ws2006/des.htm
// we permute the opiginal key
// create the shifted subkeys from it and permute them to get our
// key schedule
key_block* generate_key_schedule(key_block key){
   int i;
   //print_b(key,BYTE_SIZE);

   key_block permuted_key = permute(key, PC1, KEY_SIZE, PC1_SIZE);
   //printf("key halves after PC1:\n");
   //print_b(permuted_key,7);

   key_block* shifted_subkeys = shift_subkeys(permuted_key);
   //printf("key after shift:\n");
   //print_b(shifted_subkeys[15],7);

   key_block* key_schedule = (key_block*)malloc(sizeof(key_block) * 16);

   for(i = 0;i < KEY_ROUNDS; i++){
      key_block result = permute(shifted_subkeys[i], PC2, PC1_SIZE, PC2_SIZE);
      key_schedule[i].l = result.l;
      key_schedule[i].r = result.r;
   }
   //printf("key after PC2:\n");
   //print_b(key_schedule[15],6);

   free(shifted_subkeys);
   return key_schedule;
}
//*******************************************
//LOOKUP SBOX
//*******************************************
// Use the first and last bits as row index,
// and middle four bits as col index.
// SBOX are usually 4x16, in a 1-D array, we multiply
// row bits with 16 to simulate a 2-D array
uint32_t lookup_sbox(uint32_t group, uint32_t sbox){
   int row = group & 0x01;
   row |= ((group >> 5) & 0x01) << 1;
   int col = (group >> 1) & 0xF;
   int bit = (row * 16) + col;

   switch (sbox){
   case 0:
      return S1[bit];
      break;
   case 1:
      return S2[bit];
      break;
   case 2:
      return S3[bit];
      break;
   case 3:
      return S4[bit];
      break;
   case 4:
      return S5[bit];
      break;
   case 5:
      return S6[bit];
      break;
   case 6:
      return S7[bit];
      break;
   case 7:
      return S8[bit];
      break;
   default:
      fprintf(stderr,"Wrong SBOX seletected. Exiting program.\n");
      exit(1);
      break;
   }

   return 0;
}
//*******************************************
//SBOX TRANSFORM
//*******************************************
// Apply sbox transformations to 48-bit message block
key_block sbox_transform(key_block block){
    uint32_t groups[8] = {0};

    int i = 0;
    int j;
    // Mask all but 6 bits into groups
    for(j = 18; j >= 0; j -= 6){
        groups[i] = (block.l >> j) & 0x3F;
        groups[i+4] = (block.r >> j) & 0x3F;
        i++;
    }

    // Convert 6 bit groups to 4 bit groups
    for(j = 0; j < BYTE_SIZE; j++)
        groups[j] = lookup_sbox(groups[j], j);

    // reform the block
    block.l = 0;
    block.r = 0;

    i = 0;
    for(j = 12; j >= 0; j -= 4){
        block.l |= (groups[i] << j);
        block.r |= (groups[i+4] << j);
        i++;
    }

    return block;
}
//*******************************************
//FEISTEL
//*******************************************
// Apply Feistel function to right half of message block.
// permute block with E
// after XOR, use SBOX transformation
// PBOX permutate after and return the 32 bit block back
uint32_t feistel(uint32_t right_block, key_block key){
    // Convert 32 bit integer to 16 bit block for E permutation
    key_block block;
    block.l = right_block >> 16;
    block.r = right_block & 0xFFFF;

    block = permute(block, E, BLOCK_SIZE/2, E_SIZE);

    // XOR with subkey
    block.l ^= key.l;
    block.r ^= key.r;

    block = sbox_transform(block);
    block = permute(block, P, P_SIZE, P_SIZE);

    // return back a single 32-bit integer
    return block.r | (block.l << 16);
}
//*******************************************
//ENCODE ROUND
//*******************************************
// Do one of the 16 rounds of encryption
// this makes right block into the next left and
// have XOR encrypted right block with left block
key_block encode_round(key_block block, key_block key){
    uint32_t old_l = block.l;
    block.l = block.r;
    block.r = old_l ^ feistel(block.r, key);
    return block;
}
//*******************************************
//READ BLOCK SIZE
//*******************************************
int read_block_size(FILE *file){
   int file_size = 0;
   int number_of_blocks = 0;
   char *ret[BLOCK_SIZE/BYTE_SIZE];

   fseek(file, 0L, SEEK_END);
   file_size = ftell(file);
   fseek(file, 0L, SEEK_SET);

   number_of_blocks = file_size / BYTE_SIZE;
   if(file_size % BYTE_SIZE)
      number_of_blocks++;

   return number_of_blocks;
}
//*******************************************
//MAKE BLOCK
//*******************************************
// * Convert array of 8 characters to key_block
key_block make_block(unsigned char *chars){
    key_block block;
    block.l = 0;
    block.r = 0;

    int i = 0;
    int j;
    for(j = 24; j >= 0; j -= BYTE_SIZE){
        block.l |= chars[i] << j;
        block.r |= chars[i+4] << j;
        i++;
    }

    return block;
}
//*******************************************
//ENCODE BLOCK
//*******************************************
// Encode a 64-bit message block
// Does initial permutation to every block, prints used to test
// if encrypting, follow key schedule in order, else in reverse
// then after flipping the blocks, return final permutation
key_block encode_block(key_block block, key_block* schedule, uint32_t direction){
   int i;
    //print_b(block,BYTE_SIZE);
    block = permute(block, IP, BLOCK_SIZE, BLOCK_SIZE);
    //print_b(block,BYTE_SIZE);
    if (direction == ENCODE){
        for(i = 0; i < KEY_ROUNDS; i++)
            block = encode_round(block, schedule[i]);
    }
    else{
        for(i = KEY_ROUNDS - 1; i >= 0; i--)
            block = encode_round(block, schedule[i]);
    }

    // Reverse connect the half blocks.
    uint32_t tmp = block.l;
    block.l = block.r;
    block.r = tmp;

    return permute(block, FP, BLOCK_SIZE, BLOCK_SIZE);
}
//*******************************************
//WRITE BLOCK
//*******************************************
// Write 64 bit block to a file. Skip final bytes if padding = 1
// should be a number of bits to ignore set through encrypt function
void write_block(FILE *output, key_block block, int32_t padding){
    int offset = 0;
    unsigned char chars[BLOCK_SIZE/BYTE_SIZE];

    int i = 0;
    int j;
    for(j = 24; j >= 0; j -= BYTE_SIZE){
        chars[i] = (block.l >> j) ;
        chars[i+4] = (block.r >> j);
        i++;
    }

    if (padding)
        offset = chars[BLOCK_SIZE/BYTE_SIZE-1];

    for(j = 0; j < BLOCK_SIZE/BYTE_SIZE - offset; j++)
        fwrite(&chars[j], 1, 1, output);
}
//*******************************************
//ENCRYPT
//*******************************************
// read in plaintext by 64 bit blocks while checking if 
// block needs padding, if not, add a block of padding at the end
// if it is the first block, XOR it with IV, else XOR with previous block
// and encrypt, then write to cyphertext.
void encrypt(FILE* plaintext, FILE* cyphertext, key_block* key_schedule, key_block IV){
   int i, j;
   int fileSize = read_block_size(plaintext);
   int first = 1;
   static int padding = 0;
   static int c = 0;
   static char chars[BLOCK_SIZE/BYTE_SIZE];
   key_block m_block, c_block, x_block;

   for(j = 0; j < fileSize; j++){
      for(i = 0; i < BLOCK_SIZE/BYTE_SIZE; i++)
         if(fread(&chars[i], 1, 1, plaintext) != 1)
            padding++;

      // Change padding bytes to padding length for decryption to use
      if (padding)
         for (i = BLOCK_SIZE/BYTE_SIZE - padding; i < BLOCK_SIZE/BYTE_SIZE; i++)
            chars[i] = padding;

      m_block = make_block(chars);

      // XOR if first block, else XOR with previous block
      if(first){
         x_block.l = IV.l ^ m_block.l;
         x_block.r = IV.r ^ m_block.r;
         first = 0;
      }
      else{
         x_block.l = c_block.l ^ m_block.l;
         x_block.r = c_block.r ^ m_block.r;
      }

      c_block = encode_block(x_block, key_schedule, ENCODE);
      write_block(cyphertext, c_block, 0);
   }

   // Add a whole block of padding if there is none
   if(!padding){
      key_block padding_block;
      padding_block.l = 0x80808080;
      padding_block.r = 0x80808080;
      write_block(cyphertext, padding_block, 0);
   }
}
//*******************************************
//DECRYPT
//*******************************************
// read in cyphertext by 64 bit blocks while checking final
// block for padding, if it is the first block, after decrypting,
// XOR it with IV, else XOR with previous block and decrypt, then write
// to output file.
void decrypt(FILE* cyphertext, FILE* plaintext, key_block* key_schedule, key_block IV){
   int i, j;
   int fileSize = read_block_size(cyphertext);
   int first = 1;
   int c = 0;
   int padding = 0;
   char chars[BLOCK_SIZE/BYTE_SIZE];
   key_block m_block, c_block, x_block, prev_c_block;

   for(j = 0; j < fileSize; j++){
      for(i = 0; i < BLOCK_SIZE/BYTE_SIZE; i++){
         if(fread(&chars[i], 1, 1, cyphertext) != 1 || j == fileSize - 1)
            padding = 1;
      }

      c_block = make_block(chars);
      x_block = encode_block(c_block, key_schedule, DECODE);

      // XOR with IV if first block, else XOR with previous block
      if(first){
         m_block.l = IV.l ^ x_block.l;
         m_block.r = IV.r ^ x_block.r;
         prev_c_block.l = c_block.l;
         prev_c_block.r = c_block.r;
         first = 0;
      }
      else{
         m_block.l = prev_c_block.l ^ x_block.l;
         m_block.r = prev_c_block.r ^ x_block.r;
         prev_c_block.l = c_block.l;
         prev_c_block.r = c_block.r;
      }

      write_block(plaintext, m_block, padding);
   }
}
