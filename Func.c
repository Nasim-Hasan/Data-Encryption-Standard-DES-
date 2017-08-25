#include "Func.h"

void encryption(FILE *fp, FILE* fpkey)
{
   EVP_PKEY_CTX *ctx;
   ENGINE *eng = ENGINE_get_default_RSA();
   unsigned char *out;
   unsigned char *in;
   size_t outlen,inlen;
   EVP_PKEY *key,key1;
   FILE *fp1;
   int i;   

   // get file size and allocate memory for it
   fseek(fp,0,SEEK_END);
   inlen=ftell(fp);
   fseek(fp,0,SEEK_SET);
   in=(unsigned char*) malloc(inlen+1);

   fread(in,inlen,1,fp);

   fclose(fp); 

   in[inlen]=0;

   key = PEM_read_PUBKEY(fpkey,NULL,NULL,NULL);
   ctx = EVP_PKEY_CTX_new(key,eng);

   if (!ctx)
   {
	 printf("Can not generate the key.....");
	 exit(3);
    }


   if (EVP_PKEY_encrypt_init(ctx) <= 0)
   {
         printf("Can not encrypt the key.....");
         exit(4);
   }


   if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) <= 0)
   {
     printf("Error with padding....");
     exit(4);
   }

 /* Determine buffer length */
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
  {
     printf("Error in Buffer Length......!!");
     exit(3);
  }

  out= OPENSSL_malloc(outlen);

  if (!out)
  {
     printf("Error with memory allocation......!!");
     exit(3);

  }
 

  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
  {
    printf("Error in Encryption......!!");
    exit(4);

  }

 /* Encrypted data is outlen bytes written to buffer out */

  fp1= fopen("decrypted.key","w"); //.....Writes the decrypted session key into the output file...//

   for(i=0;i<outlen;i++)
   {
     if(fwrite(&out[i],1,1,fp1)!=1)
     {
           printf("Can not write in file.....!!!!");
           exit(2);
     }
   }
   free(in);
   free(out);
   fclose(fp1); 
   fclose(fpkey);

}

//********************************
// SIGN
//********************************
void sign(FILE* fp, FILE* prikey){
   unsigned char* text;
   unsigned char* sig = NULL;
   size_t sigLen = 0;
   int textLen = 0;
   int i = 0;
   EVP_PKEY* key = PEM_read_PrivateKey(prikey,NULL,NULL,NULL);
   EVP_MD_CTX* ctx = EVP_MD_CTX_create();

   // get file size and allocate memory for it
   fseek(fp,0,SEEK_END);
   textLen=ftell(fp);
   fseek(fp,0,SEEK_SET);
   text = (unsigned char*) malloc(textLen);

   fread(text,textLen,1,fp);

   ctx = EVP_MD_CTX_create();
   if(ctx == NULL) {
      printf("EVP_MD_CTX_create failed.\n");
      exit(3);
   }

   const EVP_MD* md = EVP_get_digestbyname("SHA256");
   if(md == NULL) {
      printf("EVP_get_digestbyname failed.\n");
      exit(3);
   }

   int rc = EVP_DigestInit_ex(ctx, md, NULL);
   if(rc != 1) {
      printf("EVP_DigestInit_ex failed.\n");
      exit(3);
   }

   rc = EVP_DigestSignInit(ctx, NULL, md, NULL, key);
   if(rc != 1) {
      printf("EVP_DigestSignInit failed.\n");
      exit(3);
   }

   rc = EVP_DigestSignUpdate(ctx, text, textLen);
   if(rc != 1) {
      printf("EVP_DigestSignUpdate failed.\n");
      exit(3);
   }

   size_t req = 0;
   rc = EVP_DigestSignFinal(ctx, NULL, &req);
   if(rc != 1) {
      printf("EVP_DigestSignFinal failed (1).\n");
      exit(3);
   }

   if(!(req > 0)) {
      printf("EVP_DigestSignFinal failed (2).\n");
      exit(3);
   }

   sig = OPENSSL_malloc(req);
   if(sig == NULL) {
      printf("OPENSSL_malloc failed.\n");
      exit(3);
   }

   sigLen = req;
   rc = EVP_DigestSignFinal(ctx, sig, &sigLen);
   if(rc != 1) {
      printf("EVP_DigestSignFinal failed (3), return code %d.\n", rc);
      exit(3);
   }

   if(rc != 1) {
      printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, sigLen);
      exit(3);
   }

   FILE* output = fopen("signature.sha2","w");
   for(i = 0; i < sigLen; i++){
      if(fwrite(&sig[i],1,1,output) != 1){
         printf("Error writing signature.sha2\n");
         exit(2);
      }
   }
   fclose(output);
   free(text);

   if(ctx) {
      EVP_MD_CTX_destroy(ctx);
      ctx = NULL;
   }
}
//********************************
// VERIFY
//********************************
void verify(FILE* fp,FILE* hfp, FILE* pubkey){
   unsigned char* text;
   unsigned char* sig = NULL;
   size_t sigLen = 0;
   int textLen = 0;
   int i = 0;
   EVP_PKEY* key = PEM_read_PUBKEY(pubkey,NULL,NULL,NULL);
   EVP_MD_CTX* ctx = EVP_MD_CTX_create();

   // get file size and allocate memory for it
   fseek(fp,0,SEEK_END);
   textLen=ftell(fp);
   fseek(fp,0,SEEK_SET);
   text = (unsigned char*) malloc(textLen);

   fread(text,textLen,1,fp);

   fseek(hfp,0,SEEK_END);
   sigLen=ftell(hfp);
   fseek(hfp,0,SEEK_SET);
   sig = (unsigned char*) malloc(sigLen);

   fread(sig,sigLen,1,hfp);

   ctx = EVP_MD_CTX_create();

   if(ctx == NULL) {
      printf("EVP_MD_CTX_create failed.");
      exit(3);
   }
   
   const EVP_MD* md = EVP_get_digestbyname("SHA256");
   if(md == NULL) {
      printf("EVP_get_digestbyname failed.");
      exit(3);
   }
   
   int rc = EVP_DigestInit_ex(ctx, md, NULL);
   if(rc != 1) {
      printf("EVP_DigestInit_ex failed.");
      exit(3);
   }
   
   rc = EVP_DigestVerifyInit(ctx, NULL, md, NULL, key);
   if(rc != 1) {
      printf("EVP_DigestVerifyInit failed.");
      exit(3);
   }
   
   rc = EVP_DigestVerifyUpdate(ctx, text, textLen);
   if(rc != 1) {
      printf("EVP_DigestVerifyUpdate failed.");
      exit(3);
   }
   
   /* Clear any errors for the call below */
   ERR_clear_error();
   rc = EVP_DigestVerifyFinal(ctx, sig, sigLen);
   if(rc != 1) {
      printf("Verification Failed to Pass, message compromised.\n\n");
      exit(1);
   }

    if(ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    printf("Verification Passed\n\n");
}

