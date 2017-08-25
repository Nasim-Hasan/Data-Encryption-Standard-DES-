#ifndef FUNC_H
#define FUNC_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "./DES/DES.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

void encryption(FILE*,FILE*);
void sign(FILE*,FILE*);
void verify(FILE*,FILE*,FILE*);

#endif
