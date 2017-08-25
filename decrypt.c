/*
 Encrypt and Sign a message.
 1) Take inputs
 2) Use DES on cyphertext to decrypt
 4) verify signature

Usage:  ./decrypt <INPUT FILE> <OUTPUT FILE> <THIRD PARTY PUBLIC KEY> <PLAINTEXT SESSION KEY FILE> <IV FILE> <SIGNATURE>

*/
#include "Func.h"

int main(int argc, char* argv[]){
   int i = 0;
   uint64_t IV = 0;
   uint64_t skey = 0;
   unsigned char IV_lenTest[17] = {EOF};
   unsigned char session_test[17] = {EOF};
   OpenSSL_add_all_algorithms();

   // Test for correct number of parameters
   if(argc < 7 || argc > 7){
      fprintf (stderr, "Usage:  %s <INPUT FILE> <OUTPUT FILE> <THIRD PARTY PUBLIC KEY> <PLAINTEXT SESSION KEY FILE> <IV FILE> <SIGNATURE> %d\n", argv[0],argc);
      exit(-1);
   }

   // Get operation to perform and file names
   FILE* input = fopen(argv[1], "r");
   FILE* output = fopen(argv[2], "w");
   FILE* third_pKey = fopen(argv[3], "r");
   FILE* d_session_key = fopen(argv[4], "rb");
   FILE* IV_file = fopen(argv[5],"r");
   FILE* sign = fopen(argv[6],"r");

   // check if files exits and can be created
   if(input == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[1]);
      exit(1);
   }
   else if(output == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[2]);
      exit(1);
   }
   else if(third_pKey == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[3]);
      exit(1);
   }
   else if(d_session_key == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[4]);
      exit(1);
   }
   else if(IV_file == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[5]);
      exit(1);
   }
   else if(sign == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[6]);
      exit(1);
   }
/************************get session key*********************************/
   if(fread(session_test,16,1,d_session_key) != 1){
      fprintf(stderr,"Problem reading %s, bytes did not match.\n",argv[5]);
      exit(1);
   }

   if(strlen(session_test) >= 16){
         skey = (uint64_t)strtoul(session_test, NULL, 16);
      }
   else{
      fprintf(stderr,"Session key must be 64 bits long (16 hex long)\n");
      exit(2);
   }
   key_block session_key;
   session_key.l = (skey >> 32);
   session_key.r = skey & 0x00000000FFFFFFFF;

   fclose(d_session_key);
   key_block* key_schedule = generate_key_schedule(session_key);

/****************************get IV*********************************/
   if(fread(IV_lenTest,16,1,IV_file) != 1){
      fprintf(stderr,"Problem reading %s, bytes did not match.\n",argv[6]);
      exit(1);
   }

   if(strlen(IV_lenTest) >= 16){
         IV = (uint64_t)strtoul(IV_lenTest, NULL, 16);
      }
   else{
      fprintf(stderr,"Key and IV must be 64 bits long (16 hex long)\n");
      exit(2);
   }

   key_block IV_halves;
   IV_halves.l = (IV >> 32);
   IV_halves.r = IV & 0x00000000FFFFFFFF;
   fclose(IV_file);

   printf("Decrpting message...");
   decrypt(input, output, key_schedule, IV_halves);
   printf(" decryption completed.\n");

   printf("Decripted message saved in %s\n\n",argv[2]);
   /*verify the encrypted file process */
   verify(input,sign,third_pKey);
   // Always close files or errors occur, inform user operation is done
   free(key_schedule);
   fclose(input);
   fclose(output);
   fclose(sign);
   fclose(third_pKey);
   printf("Operation completed successfully.\n");
   return 0;
}
