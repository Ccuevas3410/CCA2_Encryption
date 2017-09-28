#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+-------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(C) (32 bytes for SHA256) |
 * +------------+--------------------+-------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */

	// If entropy is given applly KDF - HMACSHA512 elseif is null randBytes for random key
	/*if(entropy)
	{
	//	HMAC(EVP_sha512(),*key,key_len,unsigned char*d,int n,
	//			unsinged char *md, unsigned int*md_len);

		//from
		//rkey,BLOCK_LEN,(unsigned char*)mpz_limbs_read(rcount),
		//sizeof(mp_limb_t)*mpz_size(rcount),outBuf,NULL);
	}
	else
	{
	//	randBytes(//,entLen);
	}
	return 0;*/
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	//outBuf is the CT, inBuf is the message,
	//const unsigned char *Aes = K->aesKey;
	if(IV == 0)//non IV was given
	randBytes(IV,len);//we generate random IV of size len
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//sets up context for CT
	EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,IV);//sets up for encryption
	int num;
	EVP_EncryptUpdate(ctx,outBuf,&num,inBuf,len);//does the encryption
	EVP_CIPHER_CTX_free(ctx);//free up space
	return num;//returns number of btyes written
		 /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	return 0;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	/* TODO: write this. */
	return 0;
}
