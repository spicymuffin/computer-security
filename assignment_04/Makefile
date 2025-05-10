main: signtool.c signtool.h dbgutil.c fileutil.c
	gcc -Wall -o signtool signtool.c dbgutil.c fileutil.c -lssl -lcrypto -lelf
clean:
	rm -f
	rm -f signtool
keygen:
	echo "removing old key pair\n"
	rm -f private_key.pem
	rm -f public_key.pem
	echo "generating key pair\n"
	bash keygen.sh
run:
	echo "running signtool\n"
