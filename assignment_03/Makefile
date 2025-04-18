main: cryp.c dbgutil.c fileutil.c cryp.h dbgutil.h fileutil.h
	gcc -Wall -o cryp cryp.c dbgutil.c fileutil.c -lssl -lcrypto
clean:
	rm -f cryp
# is this syntax even legal, im tryna say that run depends on target main
run: main
	./cryp enc -key shared.key -in original.txt -out encrypted.txt -tag encrypted.tag
	cat encrypted.txt
	./cryp dec -key shared.key -in encrypted.txt -tag encrypted.tag -out decrypted.txt
	cat decrypted.txt
