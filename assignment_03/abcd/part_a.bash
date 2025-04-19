openssl enc -aes256 -in part_a.txt -out part_a.ctxt
openssl enc -d -aes256 -in part_a.ctxt -out part_a.dec.txt
cat part_a.dec.txt