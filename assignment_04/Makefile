signtool: signtool.c signtool.h dbgutil.c fileutil.c cas4109.c
	gcc -Wall -o signtool signtool.c dbgutil.c fileutil.c cas4109.c -lssl -lcrypto -lelf

test_executable: test_executable.c
	gcc -Wall -o test_executable test_executable.c

sign: signtool test_executable
	echo "signing test file"
	./signtool sign -e test_executable -k private_key.pem
	chmod +x test_executable-signed

verify: signtool test_executable
	echo "verifying test file"
	./signtool verify -e test_executable-signed -k public_key.pem
	./signtool verify -e test_executable -k public_key.pem

clean:
	rm -f signtool test_executable test_executable-signed

keygen:
	echo "removing old key pair"
	rm -f private_key.pem public_key.pem
	echo "generating key pair"
	bash keygen.sh

licensechk:
	echo "licensechk"
