main: cryp.c
	gcc -o cryp cryp.c
clean:
	rm -f cryp
run: cryp
	./cryp enc -key shared.key -in original.txt -out encrypted.txt -tag encrypted.tag
	cat encrypted.txt
	./cryp dec -key shared.key -in encrypted.txt -tag encrypted.tag -out decrypted.txt
	cat decrypted.txt