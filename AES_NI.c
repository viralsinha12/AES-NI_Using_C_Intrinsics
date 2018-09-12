//this code should be first compiled with gcc compiler
//command for compiling - gcc -march=native AES_NI.c 
//which tells the compiler to product code in native language on an INTEL system.

#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <time.h>	//for using time functions

//Global variable for 128-bit key
__m128i key_schedule[20];

////key-expansion schedule////
__m128i aes_128_key_expansion(__m128i key, __m128i keygened){
	keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keygened);
}

void aes128_load_key(int8_t *enc_key){

    	//loading 128 bit value from 16byte address
	key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);

	//aes_128_key_expansion in turn calling in-built function _mm_aeskeygenassist_si128 which returns the encryption key
	//using the 128 bits of data and constant round
	key_schedule[1]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[0],0x01));
	key_schedule[2]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[1],0x02));
	key_schedule[3]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[2],0x04));
	key_schedule[4]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[3],0x08));
	key_schedule[5]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[4],0x10));
	key_schedule[6]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[5],0x20));
	key_schedule[7]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[6],0x40));
	key_schedule[8]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[7],0x80));
	key_schedule[9]  = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[8],0x1B));
	key_schedule[10] = aes_128_key_expansion(key_schedule[0],_mm_aeskeygenassist_si128(key_schedule[9],0x36));
}

void aes128_enc(int8_t *plainText,int8_t *cipherText){
    	
	//loading 128 bit value from 16byte address
	__m128i m = _mm_loadu_si128((__m128i *) plainText);int i;

	///11 round including the initial pre-processing round using aesenc and aesenclast function///
	m = _mm_xor_si128       (m, key_schedule[ 0]);
        m = _mm_aesenc_si128    (m, key_schedule[ 1]);
        m = _mm_aesenc_si128    (m, key_schedule[ 2]);
        m = _mm_aesenc_si128    (m, key_schedule[ 3]);
        m = _mm_aesenc_si128    (m, key_schedule[ 4]);
        m = _mm_aesenc_si128    (m, key_schedule[ 5]);
        m = _mm_aesenc_si128    (m, key_schedule[ 6]);
        m = _mm_aesenc_si128    (m, key_schedule[ 7]);
        m = _mm_aesenc_si128    (m, key_schedule[ 8]);
        m = _mm_aesenc_si128    (m, key_schedule[ 9]); 
        m = _mm_aesenclast_si128(m, key_schedule[10]);

	///using the inbuilt function to store the generated cipher text to a memory location//
	_mm_storeu_si128((__m128i *) cipherText, m);
}

int main(){

	double _timespent = 0.0;int i;
	clock_t _begin = clock();

	// input in binary buffer array

	//input given "mynameisviralsin" in hexadecimal
	int8_t _plain[]      = {0x6d, 0x79, 0x6e, 0x61, 0x6d, 0x65, 0x69, 0x73, 0x76, 0x69, 0x72, 0x61, 0x6c, 0x73, 0x69, 0x6e};
	//random encryptionkey used
	int8_t _enckey[]    = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	int8_t _cipher[16];
	
	//for generating keys for each round
	aes128_load_key(_enckey);

	//calling the encrypt function 1000 times
	for (i=0;i<=100000;i++)
		aes128_enc(_plain,_cipher);

	displayCipherText(_cipher,0);

	clock_t _end = clock();
	_timespent += ((double)(_end-_begin))/CLOCKS_PER_SEC;
	printf("\nExecution Time : %f \n",_timespent);
	return 1;
}

void displayCipherText(int8_t *ciphertext,int i)
{	
	printf("\nCipher : \n");
	for(i=0;i<= 15;i++)
		printf("%x ",ciphertext[i]);
	printf("\n");
}
