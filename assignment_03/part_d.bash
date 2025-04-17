# echo -n "2023148006" | sha256sum gives ccbf5b31
if openssl dgst -sha256 -verify part_d.pem -signature sigs/ccbf5b31/file1.sig sigs/ccbf5b31/file1.txt; then
    echo "VALID" >> part_d.txt
else
    echo "INVALID" >> part_d.txt
fi

if openssl dgst -sha256 -verify part_d.pem -signature sigs/ccbf5b31/file2.sig sigs/ccbf5b31/file2.txt; then
    echo "VALID" >> part_d.txt
else
    echo "INVALID" >> part_d.txt
fi

if openssl dgst -sha256 -verify part_d.pem -signature sigs/ccbf5b31/file3.sig sigs/ccbf5b31/file3.txt; then
    echo "VALID" >> part_d.txt
else
    echo "INVALID" >> part_d.txt
fi
