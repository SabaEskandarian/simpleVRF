all: bls rsa

bls:
	gcc vrf_bls.c -o vrf_bls -I/usr/include/pbc -lpbc -lgmp -lcrypto

rsa:
	gcc vrf_rsa.c -o vrf_rsa -I/usr/include/pbc -lpbc -lgmp -lcrypto
