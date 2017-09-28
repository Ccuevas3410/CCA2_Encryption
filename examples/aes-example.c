/* dumb example to illustrate AES in cbc and ctr modes. */
/*https://www.openssl.org/docs/man1.1.0/crypto/EVP_CIPHER_CTX_new.html*/
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int cbc_example()
{
	unsigned char key[32];               //making an array 
	size_t i;
	for (i = 0; i < 32; i++)
		key[i] = i;                     //storing positive i into each place of array
	AES_KEY kenc;                       //encryption key
	AES_KEY kdec;                       //decryption key
	AES_set_encrypt_key(key,256,&kenc); //declaring the encryption parameters
	AES_set_decrypt_key(key,256,&kdec); //declaring the decryption parameters
	char* message = "this is a test message :D"; //plain message
	size_t len = strlen(message);               //gets the length of the message
	size_t ctLen = (len/AES_BLOCK_SIZE +        //computes a set of operation and checks for the remaider to be 1 or 0, then multiplies to AESblockSize
			(len%AES_BLOCK_SIZE?1:0)) * AES_BLOCK_SIZE;
	unsigned char ct[512];                      // cipher text
	unsigned char pt[256];                      // plain text
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,256);
	unsigned char iv[16];
	for (i = 0; i < 16; i++) iv[i] = i;
	/* NOTE: openssl's AES_cbc_encrypt *will destroy the iv*.
	 * So you have to make sure you have a copy: */
	unsigned char iv_dec[16]; memcpy(iv_dec,iv,16);  //actual encryptions happening
	AES_cbc_encrypt((unsigned char*)message,
			ct,len,&kenc,iv,AES_ENCRYPT);      
	for (i = 0; i < ctLen; i++) {
		fprintf(stderr, "%02x",ct[i]);
	}
	fprintf(stderr, "\n");
	/* note the use of the copied iv_dec, since the original
	 * was modified by the first cbc_encrypt call. */
	AES_cbc_encrypt(ct,pt,ctLen,&kdec,iv_dec,AES_DECRYPT);
	fprintf(stderr, "%s\n",pt);
	return 0;
}

int ctr_example()
{
	unsigned char key[32];//will hold our key
	size_t i;
	for (i = 0; i < 32; i++) key[i] = i;//giving stupid values to key
	unsigned char iv[16];//will hold our IV
	for (i = 0; i < 16; i++) iv[i] = i;//giving stupid values to IV
	unsigned char ct[512];//will hold the cipher text in bits
	unsigned char pt[512];//will hold the plain text in bits
	/* so you can see which bytes were written: */
	memset(ct,0,512);//setting all values to 0
	memset(pt,0,512);//^^
	char* message = "this is a test message :D";// the plain text
	size_t len = strlen(message);//hold the len of the text
	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();//will hold the cipher text context
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))//cipher text ready for encyption
		ERR_print_errors_fp(stderr);
	int nWritten;// an int value
	if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message,len))//
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	size_t ctLen = nWritten;//ctlen will be the cipher text lenth
	for (i = 0; i < ctLen; i++) {
		fprintf(stderr, "%02x",ct[i]);//loop to output ct
	}
	fprintf(stderr, "\n");
	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work. */
	nWritten = 0;
	ctx = EVP_CIPHER_CTX_new();//refreshes ctx
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctLen))
		ERR_print_errors_fp(stderr);
	fprintf(stderr, "%s\n",pt);
	return 0;
}

int main()
{
   // return ctr_example();
    return cbc_example();
}
