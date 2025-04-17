openssl genrsa -aes256 -out part_b_private.pem 2048
openssl rsa -in part_b_private.pem -out part_b.pem -pubout
