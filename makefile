all : DESMAKE encryption decrypt
encryption: encryption.o Func.o
	gcc -ggdb -Wall -Wextra -o encrypt DES/DESFunc.o DES/des_utils.o encryption.o Func.o -lcrypto

decrypt: decrypt.o Func.o
	gcc -ggdb -Wall -Wextra -o decrypt DES/DESFunc.o DES/des_utils.o decrypt.o Func.o -lcrypto

decrypt.o: decrypt.c Func.h
	gcc -c decrypt.c

encryption.o: encryption.c Func.h
	gcc -c encryption.c

Func.o: Func.c Func.h
	gcc -c Func.c

DESMAKE:
	$(MAKE) -C ./DES/

run_e:
	./encrypt plaintext.txt cyphertext.txt PrivateKey.pem public.pem encrypted.key

run_d:
	./decrypt cyphertext.txt decryptedtext.txt PublicKey.pem decrypted.key IV.txt signature.sha2

clean:
	rm -rf *.o encrypt decrypt IV.txt cyphertext.txt decrypted.key decryptedtext.txt signature.sha2
	$(MAKE) -C ./DES/ clean
