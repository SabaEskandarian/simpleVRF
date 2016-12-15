#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int setup(RSA **rsa_pub, RSA **rsa_priv, unsigned char **proof);
int VRF(RSA *rsa_priv, char *input, unsigned char **output, unsigned char **proof, unsigned int *proofLen);
int checkVRF(RSA *rsa_pub, char *input, unsigned char *output, unsigned char *proof, unsigned int proofLen);
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
	unsigned int proofLen = 0;

	RSA *pub;
	RSA *priv;
	setup(&pub, &priv, &proof);
	printf("computing VRF on %s\n", argv[1]);
	clock_t begin = clock();
	n = VRF(priv, argv[1], &output, &proof, &proofLen);
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
	ver = checkVRF(pub, argv[1], output, proof, proofLen);
	end = clock();
	time_spent = (double) (end-begin) / CLOCKS_PER_SEC;
	printf("%d\n", ver);
	printf("time taken: %f\n", time_spent);
	printf("checking correct non-verification... %d\n", checkVRF(pub, argv[1], "glub", "glub", 4));

}


int setup(RSA **rsa_pub, RSA **rsa_priv, unsigned char **proof)
{
	*rsa_pub = PEM_read_RSA_PUBKEY(fopen("pubKey.pub", "r"), NULL, NULL, NULL);
	*rsa_priv = PEM_read_RSAPrivateKey(fopen("privKey.pem","r"), NULL, NULL, NULL);
	*proof = malloc(RSA_size(*rsa_priv));
	return 0;
}

int VRF(RSA *rsa_priv, char *input, unsigned char **output, unsigned char **proof, unsigned int *proofLen)
{
	int n = 0;
	unsigned char* hash = malloc(32);
	sha256(input, hash, strlen(input));
	RSA_sign(NID_sha256, hash, 32, *proof, proofLen, rsa_priv);
	*output = malloc(32);
	sha256(*proof, *output, *proofLen);
	return *proofLen;
}

int checkVRF(RSA *rsa_pub, char *input, unsigned char *output, unsigned char *proof, unsigned int proofLen)
{
	//1 means success, 0 means failure
	int success = 0;
	unsigned char temp[32];
	unsigned char* hash = malloc(32);
	sha256(input, hash, strlen(input));
	if(!RSA_verify(NID_sha256, hash, 32, proof, proofLen, rsa_pub)) return 0;
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
