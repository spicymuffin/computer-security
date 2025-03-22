main:
	gcc -Wall dynamic_array.c secure_house.c -o secure_house
clean:
	rm -f secure_house
debug:
	gcc -g dynamic_array.c secure_house.c -o secure_house
	gdb --args secure_house luigi 123 secretkey
