#include <pbc.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef struct p{
	char param[1024];
	pairing_t pairing;
	element_t g;
	element_t pk;
} params;

int setup(params *pp, element_t *sk);
int sign(params *pp, element_t *sk, char *input, unsigned char **signature);
int verifySig(params *pp, unsigned char *signature, char *input);
int VRF(params *pp, element_t *sk, char *input, unsigned char **output, unsigned char **proof);
int checkVRF(params *pp, char *input, unsigned char *output, unsigned char *proof, int proofLen);
int sha256(unsigned char *input, unsigned char *output, int inputLen);
void printHash(unsigned char *hash, int len);


int main(int argc, char *argv[])
{
		
	if(argc!=2)
	{
		printf("only one input\n");
		exit(0);
	}//argv[1] is our input value

	int n = 0, i = 0;
	unsigned char *output;
	unsigned char *proof;

	params public;
	element_t secKey;
	setup(&public, &secKey);
	printf("computing VRF on %s\n", argv[1]);
	clock_t begin = clock();
	n = VRF(&public, &secKey, argv[1], &output, &proof);
	clock_t end = clock();
	double time_spent = (double) (end-begin) / CLOCKS_PER_SEC;
	printf("output: ");
	printHash(output, 32);
	printf(" time taken: %f", time_spent);
	printf("\nproof size: %d", n);
	printf("\nproof: ");
	printHash(proof, n);
	printf("\n");
	int ver = 0;
	printf("checking correct verification... ");
	begin = clock();
	ver = checkVRF(&public, argv[1], output, proof, n);
	end = clock();
	time_spent = (double) (end-begin) / CLOCKS_PER_SEC;
	printf("%d\n", ver);
	printf("time taken: %f\n", time_spent);
	printf("checking correct non-verification... %d\n", checkVRF(&public, argv[1], "glub", "glub", 4));

}


int setup(params *pp, element_t *sk)
{
	size_t count = fread(pp->param, 1, 1024, fopen("a.param", "r"));
	if (!count) 
	{
			pbc_die("input error");
			return 1;
	}
	pairing_init_set_buf(pp->pairing, pp->param, count);

	element_init_G2(pp->g, pp->pairing);
	element_init_G2(pp->pk, pp->pairing);
	element_init_Zr(*sk, pp->pairing);

	element_random(pp->g);
	element_random(*sk);
	element_pow_zn(pp->pk, pp->g, *sk);
	return 0;
}

int sign(params *pp, element_t *sk, char *input, unsigned char **signature)
{
	int n = 0;
	element_t h;
	element_t sig;
	element_init_G1(h, pp->pairing);
	element_init_G1(sig, pp->pairing);
	
	unsigned char hash[32];
	sha256(input, hash, strlen(input));
	element_from_hash(h, hash, 32);

	element_pow_zn(sig, h, *sk);
	

	element_clear(h);
	n = element_length_in_bytes(sig);
	*signature = malloc(n);
	int q = element_to_bytes(*signature, sig);

	return n;
}

int verifySig(params *pp, unsigned char *signature, char *input)
{
	//return 1 means good return 0 means bad
	
	int success = 0;
	element_t sig;
	element_t h;
	element_t temp1, temp2;
	element_init_G1(h, pp->pairing);
	element_init_G1(sig, pp->pairing);
	element_init_GT(temp1, pp->pairing);
	element_init_GT(temp2, pp->pairing);
	
	element_from_bytes(sig, signature);

	unsigned char hash[32];
	sha256(input, hash, strlen(input));
	element_from_hash(h, hash, 32);

	pairing_apply(temp1, sig, pp->g, pp->pairing);
	pairing_apply(temp2, h, pp->pk, pp->pairing);
	if (!element_cmp(temp1, temp2))
		success = 1;
	else
		success = 0;

	element_clear(h);
	element_clear(temp1);
	element_clear(temp2);
	return success;
}

int VRF(params *pp, element_t *sk, char *input, unsigned char **output, unsigned char **proof)
{
	int n = 0;
	n = sign(pp, sk, input, proof);
	*output = malloc(32);
	sha256(*proof, *output, n);
	return n;
}

int checkVRF(params *pp, char *input, unsigned char *output, unsigned char *proof, int proofLen)
{
	//1 means success, 0 means failure
	int success = 0;
	unsigned char temp[32];
	if(!verifySig(pp, proof, input)) return 0;
	sha256(proof, temp, proofLen);
	if(!CRYPTO_memcmp(output, temp, 32)==0) return 0;
	success = 1;
	return success;
}

int sha256(unsigned char *input, unsigned char *output, int inputLen)
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	int md_len = 0;
	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, input, inputLen);
	EVP_DigestFinal_ex(mdctx, output, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	return md_len;
}

void printHash(unsigned char *hash, int len)
{
	int i = 0;
	for(i=0;i<len;i++)
	{
			//printf("#%d", i);
			printf("%02x",hash[i]);
	}
	printf("\n");
}
