main: cryp.c dbgutil.c fileutil.c cryp.h dbgutil.h fileutil.h
	gcc -Wall -o cryp cryp.c dbgutil.c fileutil.c -lssl -lcrypto
clean:
	rm -f cryp
run:
	./cryp enc -key shared.key -in original.txt -out encrypted.txt -tag encrypted.tag
	cat encrypted.txt
	./cryp dec -key shared.key -in encrypted.txt -tag encrypted.tag -out decrypted.txt
	cat decrypted.txt
