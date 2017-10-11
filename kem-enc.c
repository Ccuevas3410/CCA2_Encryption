/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <openssl/hmac.h>
#include <string.h>  /* memcpy */
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "ske.h"
#include "rsa.h"
#include "prf.h"
#define HM_LEN 32


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	/*READ FIRST: so here for the kem-encrypt what i did is basically
	 * generate a SKE key, then I take that SK and encrypt it using RSA then
	 * hash it. The actual encryption of the fnIn file is encrypted using
	 * ske_encrypt_file function*/

	// SKE KEYGEN
	unsigned char* x = malloc(HASHLEN); //tempholder for SK
	SKE_KEY SK;  //generates the actual hmcKey & aesKey holder
	ske_keyGen(&SK,x,HASHLEN); //generates both hmc&aesKey

	// RSA ENCRYPTION
	unsigned char* pt = malloc(128); //will hold the SK
	unsigned char* ct = malloc(128); //encrypt SK
	rsa_keyGen(HASHLEN,K);               //generates rsa keys (n,p,q,e,d)

	// HASH FUNCTION
	//we do a hash on the plain text so that when we check the hash on the
	//pt when decrypting we can confirm that the key hasnt been tempered.
	memcpy(pt,SK.hmacKey,HASHLEN); // first half holds HMACkey
	memcpy(pt+HASHLEN,SK.aesKey,HASHLEN);    // second half holds aeskey
	unsigned char* tempHash = malloc(64);
	HMAC(EVP_sha512(),KDF_KEY,HASHLEN,pt,64,tempHash,NULL); // hash256 on the plain text, which are the keys
	rsa_encrypt(ct,pt,HASHLEN,K); // rsa encrypt the SK in pt
	memcpy(ct+HASHLEN+HASHLEN,tempHash,64);

	int fdOut;         
	fdOut = open(fnOut,O_RDWR|O_CREAT,S_IRWXU);
	// Error Check
	if (fdOut < 0){
	    perror("Error:");
	     return 1;
	 }

	int wc = write(fdOut,ct,128);
	// Error Check
	if ( wc < 0){
	     perror("Error:");
		return 1;
	 }
  
	// Close Files & Delete Mappings 
	close(fdOut);
	
	//encrypting the file
	unsigned char* IV=malloc(16);
	randBytes(IV,16);
	ske_encrypt_file(fnOut+128,fnIn,&SK,IV,0);     //assuming that ske_encrypt_file works, after masking the SK into RSA to share we just encrypt the file using SKE
	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnout, const char* fnin, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key */
	/* step 2: check decapsulation */
	/* step 3: derive key from ephemKey and decrypt data. */

	/*READ FIRST:here is the backwar concept, we first open the file that we
	 * encrypted. The first thing is to get the SK back by decrypting the
	 * RSA, after the we optained the plain text in this case is the SK and
	 * we check the hmac, from there we extract both hmackey and aeskey. now
	 * we proceed to decrypt the actual message and write it out into the fnout file.*/

	  int fdIn, fdOut;        // File Descriptor 
          struct stat st;         // File Stats
          size_t fileSize;   // File Size & Bytes written
          unsigned char* mappedFile;      // for memory map (mmap)
   
          // Open Encrypted File with Read Only Capability
          fdIn = open(fnin,O_RDONLY);
          // Error Check
          if (fdIn < 0){
              perror("Error:");
                  return 1;
          }
         // Get File Size
         stat(fnin, &st);
         fileSize = st.st_size;

	 mappedFile = mmap(NULL, fileSize, PROT_READ,MAP_PRIVATE, fdIn, 0);
         // Error Check
         if (mappedFile == MAP_FAILED)
		 {
                perror("Error:");
                  return 1;
         }	
	size_t keyLen = rsa_numBytesN(K);  //gets size of the Key length 
	unsigned char* Encryptedfilekey = malloc(keyLen); //allocate a space to store the ct
	memcpy(Encryptedfilekey, mappedFile, keyLen); 

	//RSA Decrypt
	unsigned char* Decryptedfilekey = malloc(keyLen);  //holds the decrypted text from RSA
	rsa_decrypt(Decryptedfilekey,Encryptedfilekey,keyLen,K); //decrypts the key

        // generate hash using cyphertext to ensure integrity of CT
        unsigned char* tempHash=malloc(64); // to hold return of HMAC
        HMAC(EVP_sha256(),KDF_KEY,HM_LEN,Decryptedfilekey,keyLen,tempHash,NULL);//ctBuf,ctSize

	unsigned char* symk = malloc(64);
	memcpy(symk,mappedFile+keyLen,64);
	size_t i;
         for (i=0;i<32;i++) 
	 {
		if(symk[i] != tempHash[i] ) return -1;
	 }

	SKE_KEY SK;
	memcpy(SK.hmacKey,Decryptedfilekey,32);	 
	memcpy(SK.aesKey,Decryptedfilekey,32);	 

	// Decryption
	size_t SKE_size = st.st_size - keyLen;
	unsigned char* SKE_CT = malloc(SKE_size);
	memcpy(SKE_CT,mappedFile+keyLen,64);
	
	unsigned char* PT = malloc(SKE_size);
	ske_decrypt(PT,SKE_CT,SKE_size,&SK);

	fdOut = open(fnout,O_RDWR|O_CREAT,S_IRWXU);
	// Error Check
	if (fdOut < 0){
	    perror("Error:");
	     return 1;
	 }


	int wc = write(fdOut,PT,SKE_size);
        // Error Check
        if ( wc < 0){
             perror("Error:");
                return 1;
         }
  
        // Close Files & Delete Mappings 
        close(fdIn);
        close(fdOut);
        munmap(mappedFile, fileSize);

	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */

	RSA_KEY K; 
	switch (mode) {
		case ENC:
			kem_encrypt(fnOut,fnIn,&K);
			break;
		case DEC:
			kem_decrypt(fnOut,fnIn,&K);
			break;
		case GEN:
			rsa_keyGen(nBits,&K);
			break;
		default:
			return 1;
	}
	rsa_shredKey(&K);

	return 0;
}
