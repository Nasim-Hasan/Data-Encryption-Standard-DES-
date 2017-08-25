all : DES
DES: DESFunc.o DES.o des_utils.o
	gcc -o DES DESFunc.o DES.o des_utils.o -Wall

DES.o: DES.c DES.h
	gcc -c DES.c

DESFunc.o: DESFunc.c DES.h
	gcc -c DESFunc.c

des_utils.o: des_utils.c DES.h
	gcc -c des_utils.c

run_e:
	./DES -enc test.txt out.txt 133457799BBCDFF1 6b8b4567327b23c6
run_d:
	./DES -dec out.txt decrypted.txt 133457799BBCDFF1 6b8b4567327b23c6
clean:
	rm -rf *.o DES decrypted.txt out.txt key_IV.txt
