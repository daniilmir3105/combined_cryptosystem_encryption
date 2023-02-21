#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


unsigned int rol(unsigned int a, int n) {
	int t1, t2;
	n = n % (sizeof(a)*8);
	t1 = a << n;
	t2 = a >> (sizeof(a)*8 - n);
	return t1 | t2;
}


unsigned int sbox[8][16] = 
{
	{  4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3 },
	{ 14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9 },
	{  5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11 },
	{  7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3 },
	{  6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2 },
	{  4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14 },
	{ 13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12 },
	{  1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12 }  
};

#define GOST_ENCRYPT_ROUND(k1, k2) \
t = (k1) + r; \
l ^= (sbox[0][(t & 0xf0000000) >> 28] << 28) | \
	(sbox[1][(t & 0x0f000000) >> 24] << 24) | \
	(sbox[2][(t & 0x00f00000) >> 20] << 20) | \
	(sbox[3][(t & 0x000f0000) >> 16] << 16) | \
	(sbox[4][(t & 0x0000f000) >> 12] << 12) | \
	(sbox[5][(t & 0x00000f00) >> 8] << 8) | \
	(sbox[6][(t & 0x000000f0) >> 4] << 4) | \
	(sbox[7][(t & 0x0000000f)]); \
t = rol(l, 11); \
t = (k2) + l; \
r ^= (sbox[0][(t & 0xf0000000) >> 28] << 28) | \
	(sbox[1][(t & 0x0f000000) >> 24] << 24) | \
	(sbox[2][(t & 0x00f00000) >> 20] << 20) | \
	(sbox[3][(t & 0x000f0000) >> 16] << 16) | \
	(sbox[4][(t & 0x0000f000) >> 12] << 12) | \
	(sbox[5][(t & 0x00000f00) >> 8] << 8) | \
	(sbox[6][(t & 0x000000f0) >> 4] << 4) | \
	(sbox[7][(t & 0x0000000f)]); \
r = rol(r, 11); \


#define GOST_ENCRYPT(key) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[0], key[1]) \
GOST_ENCRYPT_ROUND(key[2], key[3]) \
GOST_ENCRYPT_ROUND(key[4], key[5]) \
GOST_ENCRYPT_ROUND(key[6], key[7]) \
GOST_ENCRYPT_ROUND(key[7], key[6]) \
GOST_ENCRYPT_ROUND(key[5], key[4]) \
GOST_ENCRYPT_ROUND(key[3], key[2]) \
GOST_ENCRYPT_ROUND(key[1], key[0]) \
t = r; \
r = l; \
l = t; \


typedef struct {
	unsigned int sum[8];
	unsigned int len[8];
	unsigned int hash[8];
	unsigned char message_block[32];
	size_t message_block_size;
	unsigned char result[32];
} HASH;


void initHash(HASH * hash){
	memset(hash->sum, 0, 32);
	memset(hash->len, 0, 32);
	memset(hash->hash, 0, 32);
	memset(hash->message_block, 0, 32);
	hash->message_block_size = 0;
}



void psiConversion(unsigned int * n) {
	unsigned short tmp[16];
	for(size_t i = 0, j = 0; i < 16 || j < 8; i+=2,j++) {
		tmp[i] = (unsigned short)((n[j] & 0xffff0000) >> 16);
		tmp[i+1] = (unsigned short)(n[j] & 0x0000ffff);
	}

	for (size_t i = 7, j = 14; i >=1; i--, j-=2) {
		n[i] = (((unsigned int) tmp[j-1]) << 16) + ((unsigned int) tmp[j]);
	}

	n[0] = (((unsigned int)(tmp[15] ^ tmp[14] ^ tmp[13] ^ tmp[12] ^ tmp[3] ^ tmp[0])) << 16) + ((unsigned int) tmp[0]); 
}



void compressionFunction(unsigned int * h, unsigned int * m) {
	printf("START compression function\n");
	int i;
	unsigned int l, r, t, key[8], u[8], v[8], w[8], s[8];

	memcpy(u, m, sizeof(u));
	memcpy(v, h, sizeof(u));

	//Simultaneously calculate KEYi and si from hi-1  by GOST-28147-89
	for (i = 0; i < 8; i += 2) {
		w[0] = u[0] ^ v [0];
		w[1] = u[1] ^ v [1];
		w[2] = u[2] ^ v [2];
		w[3] = u[3] ^ v [3];
		w[4] = u[4] ^ v [4];
		w[5] = u[5] ^ v [5];
		w[6] = u[6] ^ v [6];
		w[7] = u[7] ^ v [7];

		//P-function.
		key[0] = w[0] & 0xff000000 | ((w[2] & 0xff000000) >> 8) | 
		((w[4] & 0xff000000) >> 16) | ((w[6] & 0xff000000) >> 24); // fi(32) = 32 fi(31) = 24 fi(30) = 16 fi(29) = 8
		
		key[1] = ((w[0] & 0x00ff0000) << 8 ) | (w[2] & 0x00ff0000) | 
		((w[4] & 0x00ff0000) >> 8) | ((w[6] & 0x00ff0000) >> 16); // fi(28) = 31 fi(27) = 23 fi(26) = 15 fi(25) = 7
		
		key[2] = ((w[0] & 0x0000ff00 ) << 16)  | ((w[2] & 0x0000ff00) << 8) | 
		(w[4] & 0x0000ff00) | ((w[6] & 0x0000ff00) >> 8);  // fi(24) = 30 fi(23) = 22 fi(22) = 14 fi(21) = 6
		
		key[3] = ((w[0] & 0x000000ff) << 24) | ((w[2] & 0x000000ff) << 16) | 
		((w[4] & 0x000000ff) << 8) | (w[6] & 0x000000ff);  // fi(20) = 29 fi(19) = 21 fi(18) = 13 fi(17) = 5
		
		key[4] = w[1] & 0xff000000 | ((w[3] & 0xff000000) >> 8) | 
		((w[5] & 0xff000000) >> 16) | ((w[7] & 0xff000000) >> 24);  // fi(16) = 28 fi(15) = 20 fi(14) = 12 fi(13) = 4
		
		key[5] = ((w[1] & 0x00ff0000) << 8 ) | (w[3] & 0x00ff0000) | 
		((w[5] & 0x00ff0000) >> 8) | ((w[7] & 0x00ff0000) >> 16);  // fi(12) = 27 fi(11) = 19 fi(10) = 11 fi(9) = 3
		
		key[6] = ((w[1] & 0x0000ff00 ) << 16)  | ((w[3] & 0x0000ff00) << 8) | 
		(w[5] & 0x0000ff00) | ((w[7] & 0x0000ff00) >> 8);  // fi(8) = 26 fi(7) = 18 fi(6) = 10 fi(5) = 2
		
		key[7] = ((w[1] & 0x000000ff) << 24) | ((w[3] & 0x000000ff) << 16) | 
		((w[5] & 0x000000ff) << 8) | (w[7] & 0x000000ff);  // fi(4) = 32 fi(3) = 17 fi(2) = 9 fi(1) = 1

		r = h[i+1];
		l = h[i];

		//GOST-28147-89 encryption
		GOST_ENCRYPT(key);		


		s[i] = l;
		s[i+1] = r;

		if (i == 6)
			break;

		l = u[6] ^ u[4];
		r = u[7] ^ u[5];
		u[0] = l;
		u[1] = r;
		u[2] = u[0];
		u[3] = u[1];
		u[4] = u[2];
		u[5] = u[3];
		u[6] = u[4];
		u[7] = u[5];

		if (i == 2) {
			u[0] ^= 0xFF00FFFF;
			u[1] ^= 0x000000FF;
			u[2] ^= 0xFF0000FF;
			u[3] ^= 0x00FFFF00;
			u[4] ^= 0x00FF00FF;
			u[5] ^= 0x00FF00FF;
			u[6] ^= 0xFF00FF00;
			u[7] ^= 0xFF00FF00;
		}

		l = v[4];
		r = v[5];
		v[4] = v[0];
		v[5] = v[1];
		v[0] = v[2] ^ l;
		v[1] = v[3] ^ r;
		l ^= v[6];
		r ^=  v[7];
		v[6] = v[2];
		v[7] = v[3];
		v[2] = l;
		v[3] = r;
	}

	for (size_t k = 0; k < 12; k++)
		psiConversion(s);

	v[0] = m[0] ^ s[0];
	v[1] = m[1] ^ s[1];
	v[2] = m[2] ^ s[2];
	v[3] = m[3] ^ s[3];
	v[4] = m[4] ^ s[4];
	v[5] = m[5] ^ s[5];
	v[6] = m[6] ^ s[6];
	v[7] = m[7] ^ s[7];

	psiConversion(v);

	u[0] = v[0] ^ h[0];
	u[1] = v[1] ^ h[1];
	u[2] = v[2] ^ h[2];
	u[3] = v[3] ^ h[3];
	u[4] = v[4] ^ h[4];
	u[5] = v[5] ^ h[5];
	u[6] = v[6] ^ h[6];
	u[7] = v[7] ^ h[7];

	for (size_t k = 0; k < 61; k++)
		psiConversion(u);

	h[0] = u[0];
	h[1] = u[1];
	h[2] = u[2];
	h[3] = u[3];
	h[4] = u[4];
	h[5] = u[5];
	h[6] = u[6];
	h[7] = u[7];

	printf("--------IN compression function-------\n");
	for (size_t k = 0; k < 8; k++) {
		printf("%x", h[k]);
	}
	printf("\n--------IN compression function-------\n");
	printf("END compression function\n");
}



void gostHashIteration(HASH * hash, const unsigned char * message_block, size_t bits) {
	printf("START gostHashIteration\n");
	int i,j;
	unsigned int a, b, cf, m[8];
	j = 0;
	cf = 0;
	
	for (i = 0; i < 8; i++) {
		a = ((unsigned int) message_block[j + 3]) |
			(((unsigned int) message_block[j + 2]) << 8) |
			(((unsigned int) message_block[j + 1]) << 16) |
			(((unsigned int) message_block[j]) << 24);
		j += 4;
		m[i] = a;
		b = hash->sum[i];
		cf = cf + a + b;
		hash->sum[i] = cf;
		cf = (cf < b || cf < a) ? 1 : 0;
	}

	hash->len[0] += bits;
	//if carry flag
	if (hash->len[0] < bits)
		hash->len[1]++;

	compressionFunction(hash->hash, m);
	printf("END gostHashIteration\n\n");
}

void lastIteration(HASH * hash);

void gostHash(HASH * hash, const unsigned char * message, size_t len) {
	initHash(hash);
	size_t i,j;
	j = 0;
	i = hash->message_block_size;

	//Check message length <= 256 bits
	for (; j < len && i < 32; i++, j++ )
		hash->message_block[i] = message[j];

	if (i < 32) {
		hash->message_block_size = i;
		lastIteration(hash);
		return;
	}

	gostHashIteration(hash, hash->message_block, 256);

	for (; j + 32 < len; j += 32) {
		gostHashIteration(hash, &message[j], 256);
	}

	i = 0;
	for (; j < len; i++, j++ )
		hash->message_block[i] = message[j];
	hash->message_block_size = i;
	lastIteration(hash);
}


void lastIteration(HASH * hash) {
	printf("START LastIteration\n");
	int shift = 32 - hash->message_block_size;

	if (hash->message_block_size > 0) {
		for (int k = hash->message_block_size - 1, j = 31; k >= 0; k--, j--)
			hash->message_block[j] = hash->message_block[k];

		for (int k = 0; k < shift; k++)
			hash->message_block[k] = 0;
		
		gostHashIteration(hash, hash->message_block, hash->message_block_size << 3);
	}


	compressionFunction(hash->hash, hash->len);
	printf("\n");
	compressionFunction(hash->hash, hash->sum);

	unsigned int t;
	for(int i = 0, j = 0; i < 8; i++, j+= 4) {
		t = hash->hash[i];
		hash->result[j] = (unsigned char) (t >> 24);
		hash->result[j+1] = (unsigned char) (t >> 16);
		hash->result[j+2] = (unsigned char)(t >> 8);
		hash->result[j+3] = (unsigned char) t;
	}
	printf("END LastIteration\n");
}
