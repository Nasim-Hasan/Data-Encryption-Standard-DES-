/*
DES-CBC cryptography program compatible with OpenSSL
Command is inputed through argument at command line as such:

 ./DES <OPERATION> <INPUT FILE> <OUTPUT FILE> [<HEX KEY>] [<HEX IV>]
*/
#include "DES.h"

void main(int argc, char* argv[]){
   char* operation;
   char* key_lenTest;
   char* IV_lenTest;
   int flag = 1;
   uint64_t key = 0;
   uint64_t IV = 0;

  //seed random generador
   srand48(123456789);

   // Test for correct number of parameters
   if(argc < 4 || argc > 6){
      fprintf (stderr, "Usage:  %s <OPERATION> <INPUT FILE> <OUTPUT FILE> [<HEX KEY>] [<HEX IV>]\n", argv[0]);
      fprintf(stderr, "OPERATION must be declared as:\n -enc for encryption\n -dec for decryption.\n\n");
      exit(1);
   }

   // Get operation to perform and file names
   operation = argv[1];
   char* input_name = argv[2];
   char* output_name = argv[3];
   FILE* input = fopen(input_name, "r");
   FILE* output = fopen(output_name, "w");
   
   // Check arguments
   // check if files exits and can be created
   if( input == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n",  input_name);
      exit(1);
   }
   else if( output == NULL){
      fprintf(stderr,"File %s could not be found. Make sure file exist or is not mispelled.\n",  output_name);
      exit(1);
   }

   // Check for a key and IV, if none, generate both
   // if only a key is inserted, generate IV and check key size
   // if both are inserted, check length of both, close if not 16 char long
   if(argc == 4){
      printf("Generating random 64bit key...\n");
      key = rand();
      key = (key << 32) | rand();
      IV = rand();
      IV = (IV << 32) | rand();
      flag = 0;
   }
   else if(argc == 5){
      key_lenTest = argv[4];
      if(strlen(key_lenTest) == 16)
         key = (uint64_t)strtoul(argv[4], NULL, 16);
      else{
         fprintf(stderr,"Key must be 64 bits long (16 hex long)\n");
         exit(1);
      }
      IV = rand();
      IV = (IV << 32) | rand();
   }
   else if(argc == 6){
      key_lenTest = argv[4];
      IV_lenTest = argv[5];
      if(strlen(key_lenTest) == 16 && strlen(IV_lenTest) == 16){
         key = (uint64_t)strtoul(argv[4], NULL, 16);
         IV = (uint64_t)strtoul(argv[5], NULL, 16);
      }
      else{
         fprintf(stderr,"Key and IV must be 64 bits long (16 hex long)\n");
         exit(1);
      }
   }

   // split key and IV into two halves
   key_block key_halves;
   key_halves.l = (key >> 32);
   key_halves.r = key & 0x00000000FFFFFFFF;

   key_block IV_halves;
   IV_halves.l = (IV >> 32);
   IV_halves.r = IV & 0x00000000FFFFFFFF;

   //printf("key halves before:\n left = 0x%x\n right = 0x%x\n\n",key_halves.l,key_halves.r);

   key_block* key_schedule = generate_key_schedule(key_halves);

   // check for operation to run, if not correctly done, close
   if(strcmp(operation, ACTION_ENCRYPT) == 0){
      printf("Key will be stored in a text file key_IV.txt\n\n");

      char* key_name = "key_IV.txt";
      FILE* key_file = fopen(key_name,"w");

      // store Key and IV in a file accesable to user
      fprintf(key_file,"%llx\n",(unsigned long long)key);
      fprintf(key_file,"%llx",(unsigned long long)IV);
      fclose(key_file);

      printf("Encrpting...");
      encrypt(input, output, key_schedule, IV_halves);
      printf(" encryption completed.\n");
   }
   else if(strcmp(operation, ACTION_DECRYPT) == 0 && flag){
      printf("Decrypting...");
      decrypt(input, output, key_schedule, IV_halves);
      printf(" decryption completed.\n");
   }
   else if(flag){
      fprintf(stderr, "OPERATION must be declared as:\n -enc for encryption\n -dec for decryption.\n\n");
      exit(1);
   }
   else{
      fprintf(stderr, "Decryption needs to include a key and IV in that order.\nClosing\n\n");
      exit(1);
   }

   // Always close files or errors occur, inform user operation is done
   free(key_schedule);
   fclose(input);
   fclose(output);
   printf("Operation completed successfully.\n");
}
