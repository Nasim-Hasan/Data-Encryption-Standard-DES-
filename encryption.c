/*
 Encrypt and Sign a message.
 1) Take inputs
 2) Get session key
 3) Use DES on plaintext
 4) Sign ciphertext
 5) Output file

 ./encryption <INPUT FILE> <OUTPUT FILE> <OWN PRIVATE KEY> <THIRD PARTY PUBLIC KEY> <ENCRYPTED SESSION KEY>
*/
#include "Func.h"

int main(int argc, char* argv[]){
   // Initial variables
   int i = 0;
   uint64_t IV = 0;
   uint64_t skey = 0;
   unsigned char session_test[16];
   srand48(123456789);
   OpenSSL_add_all_algorithms();

   // Test for correct number of parameters
   if(argc < 6 || argc > 6){
      fprintf (stderr, "Usage:  %s <INPUT FILE> <OUTPUT FILE> <OWN PRIVATE KEY> <THIRD PARTY PUBLIC KEY> <ENCRYPTED SESSION KEY>\n", argv[0]);
      exit(1);
   }

   // Get operation to perform and file names
   FILE* input = fopen(argv[1], "r");
   FILE* output = fopen(argv[2], "w");
   FILE* private_key = fopen(argv[3], "r");
   FILE* third_pKey = fopen(argv[4], "r");
   FILE* e_session_key = fopen(argv[5], "r");

   // check if files exits and can be created
   if(input == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[1]);
      exit(1);
   }
   else if(output == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[2]);
      exit(1);
   }
   else if(private_key == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[3]);
      exit(1);
   }
   else if(third_pKey == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[4]);
      exit(1);
   }
   else if(e_session_key == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n", argv[5]);
      exit(1);
   }

   // program to decrypt ssession key in openssl
   printf("Getting session key...");
   encryption(e_session_key,third_pKey);
   printf("Session key obtained\n\n");

   // get the session
   FILE* d_session_key = fopen("decrypted.key","rb");
   for(i = 0; i < 8; i++){
      if(fread(&session_test[i],1,1,d_session_key) != 1){
         fprintf(stderr,"Problem reading %s, bytes did not match.\n",argv[5]);
      exit(2);
      }
   }

   fclose(d_session_key);
   int offset = 0;
   uint64_t temp = 0;
   for(i = 7; i >= 0; i--){
      temp = session_test[i];
      skey = skey | (temp << offset);
      offset += 8;
   }

   // store session key into plaintext
   FILE* key_file = fopen("decrypted.key","w");
   fprintf(key_file,"%llx",(unsigned long long)skey);
   fclose(key_file);

   // get the session key and IV into block for DES program
   key_block session_key;
   session_key.l = (skey >> 32);
   session_key.r = skey & 0x00000000FFFFFFFF;

   // get key schedule
   key_block* key_schedule = generate_key_schedule(session_key);

   key_block IV_halves;
   IV_halves.l = rand();
   IV_halves.r = rand();
   IV = (IV | IV_halves.l) << 32;
   IV = IV | IV_halves.r;

   printf("IV will be stored in a text file IV.txt\n\n");

   // store Key and IV in a file accesable to user
   key_file = fopen("IV.txt","w");
   fprintf(key_file,"%llx",(unsigned long long)IV);
   fclose(key_file);

   printf("Encrpting message...");
   encrypt(input, output, key_schedule, IV_halves);
   printf(" encryption completed.\n");
   free(key_schedule);
   fclose(input);
   fclose(output);

   /* signing the encrypted file process */
   output = fopen(argv[2], "r");
   printf("Signing cypher...");
   sign(output,private_key);
   printf(" signed\n\n");

   // Always close files or errors occur, inform user operation is done
   fclose(output);
   fclose(private_key);

   printf("Operation completed successfully.\n");
   return 0;
}
