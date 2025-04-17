openssl dgst -sha256 -sign part_b_private.pem -out part_c.sig part_c.txt
# verify the signature
openssl dgst -sha256 -verify part_b.pem -signature part_c.sig part_c.txt
