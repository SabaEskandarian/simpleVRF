make: crypto.c
	gcc crypto.c -o vrf -I/usr/include/pbc -lpbc -lgmp -lcrypto
