/*
	This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
	and it is hereby released to the general public under the following terms:
	Redistribution and use in source and binary forms, with or without modification, are permitted.

	Name: JtR PBKDF2 HMAC SHA256 format
	Status: working, archive

	Tested on 4770k:
	../run/john -test -format=pbkdf2-sha512
	Benchmarking: pbkdf2-sha512, CPU generic, rounds=12000 [PBKDF2-SHA512]... DONE
	Raw:	47.5 c/s real, 48.0 c/s virtual
*/
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include "misc.h"
#include "arch.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL		"pbkdf2-sha512"
#define FORMAT_NAME		"CPU generic"
#define ALGORITHM_NAME		"PBKDF2-SHA512"

#define BENCHMARK_COMMENT	", rounds=12000"
#define BENCHMARK_LENGTH	-1
#define KEYS_PER_CRYPT 1

#define BINARY_ALIGN	8
#define SALT_ALIGN	1

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int
#define uint64_t		unsigned long long int

#define PLAINTEXT_LENGTH	15
#define BINARY_SIZE		64
#define	SALT_SIZE		sizeof(grub_salt)

#define GRUB_PREFIX		"grub.pbkdf2.sha512."

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

typedef struct {
	uint8_t length;
	uint8_t v[15];
} grub_pass;

typedef struct {
  uint64_t hash[8]; /** 512bits **/
} grub_crack;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	uint32_t rounds;  /** 120000 by default **/
	uint64_t hash[8]; /** 512bits **/
} grub_salt;


////////////////////////////////////////////////////////////////////////////////
# define SWAP64(n) \
  ((((uint64_t)(n)) << 56)					\
   | ((((uint64_t)(n)) & 0xff00) << 40)			\
   | ((((uint64_t)(n)) & 0xff0000) << 24)			\
   | ((((uint64_t)(n)) & 0xff000000) << 8)			\
   | ((((uint64_t)(n)) >> 8) & 0xff000000)			\
   | ((((uint64_t)(n)) >> 24) & 0xff0000)			\
   | ((((uint64_t)(n)) >> 40) & 0xff00)			\
   | (((uint64_t)(n)) >> 56))

#define rol(x,n) ((x << n) | (x >> (64-n)))
#define ror(x,n) ((x >> n) | (x << (64-n)))
#define Ch(x,y,z) ((x & y) ^ ( (~x) & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) ((ror(x,28))  ^ (ror(x,34)) ^ (ror(x,39)))
#define Sigma1(x) ((ror(x,14))  ^ (ror(x,18)) ^ (ror(x,41)))
#define sigma0(x) ((ror(x,1))  ^ (ror(x,8)) ^(x>>7))
#define sigma1(x) ((ror(x,19)) ^ (ror(x,61)) ^(x>>6))

#define INIT_A	0x6a09e667f3bcc908LL
#define INIT_B	0xbb67ae8584caa73bLL
#define INIT_C	0x3c6ef372fe94f82bLL
#define INIT_D	0xa54ff53a5f1d36f1LL
#define INIT_E	0x510e527fade682d1LL
#define INIT_F	0x9b05688c2b3e6c1fLL
#define INIT_G	0x1f83d9abfb41bd6bLL
#define INIT_H	0x5be0cd19137e2179LL

#define SHA512_DIGEST_LENGTH	64

#define SHA512(a, b, c, d, e, f, g, h, w) \
	{ \
	uint64_t t1, t2; \
	int i; \
	for (i = 0; i < 16; i++) { \
		t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g); \
		t2 = Maj(a, b, c) + Sigma0(a); \
		h = g; \
		g = f; \
		f = e; \
		e = d + t1; \
		d = c; \
		c = b; \
		b = a; \
		a = t1 + t2; \
	} \
	for (i = 16; i < 80; i++) { \
		w[i & 15] =sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i -16) & 15] + w[(i - 7) & 15]; \
		t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g); \
		t2 = Maj(a, b, c) + Sigma0(a); \
		h = g; \
		g = f; \
		f = e; \
		e = d + t1; \
		d = c; \
		c = b; \
		b = a; \
		a = t1 + t2; \
	} \
	}
	
#define GET_WORD_64(n,b,i)\
{\
    (n) = ( (uint64_t) (b)[(i)    ] << 56 )\
        | ( (uint64_t) (b)[(i) + 1] << 48 )\
        | ( (uint64_t) (b)[(i) + 2] << 40 )\
        | ( (uint64_t) (b)[(i) + 3] << 32 )\
        | ( (uint64_t) (b)[(i) + 4] << 24 )\
        | ( (uint64_t) (b)[(i) + 5] << 16 )\
        | ( (uint64_t) (b)[(i) + 6] <<  8 )\
        | ( (uint64_t) (b)[(i) + 7]       );\
}

#define PUT_WORD_64(n,b,i)\
{\
    (b)[(i)    ] = (uint8_t) ( (n) >> 56 );\
    (b)[(i) + 1] = (uint8_t) ( (n) >> 48 );\
    (b)[(i) + 2] = (uint8_t) ( (n) >> 40 );\
    (b)[(i) + 3] = (uint8_t) ( (n) >> 32 );\
    (b)[(i) + 4] = (uint8_t) ( (n) >> 24 );\
    (b)[(i) + 5] = (uint8_t) ( (n) >> 16 );\
    (b)[(i) + 6] = (uint8_t) ( (n) >>  8 );\
    (b)[(i) + 7] = (uint8_t) ( (n)       );\
}

static grub_salt global_salt[1];
static uint64_t k[] = {
	0x428a2f98d728ae22LL, 0x7137449123ef65cdLL, 0xb5c0fbcfec4d3b2fLL,
	    0xe9b5dba58189dbbcLL,
	0x3956c25bf348b538LL, 0x59f111f1b605d019LL, 0x923f82a4af194f9bLL,
	    0xab1c5ed5da6d8118LL,
	0xd807aa98a3030242LL, 0x12835b0145706fbeLL, 0x243185be4ee4b28cLL,
	    0x550c7dc3d5ffb4e2LL,
	0x72be5d74f27b896fLL, 0x80deb1fe3b1696b1LL, 0x9bdc06a725c71235LL,
	    0xc19bf174cf692694LL,
	0xe49b69c19ef14ad2LL, 0xefbe4786384f25e3LL, 0x0fc19dc68b8cd5b5LL,
	    0x240ca1cc77ac9c65LL,
	0x2de92c6f592b0275LL, 0x4a7484aa6ea6e483LL, 0x5cb0a9dcbd41fbd4LL,
	    0x76f988da831153b5LL,
	0x983e5152ee66dfabLL, 0xa831c66d2db43210LL, 0xb00327c898fb213fLL,
	    0xbf597fc7beef0ee4LL,
	0xc6e00bf33da88fc2LL, 0xd5a79147930aa725LL, 0x06ca6351e003826fLL,
	    0x142929670a0e6e70LL,
	0x27b70a8546d22ffcLL, 0x2e1b21385c26c926LL, 0x4d2c6dfc5ac42aedLL,
	    0x53380d139d95b3dfLL,
	0x650a73548baf63deLL, 0x766a0abb3c77b2a8LL, 0x81c2c92e47edaee6LL,
	    0x92722c851482353bLL,
	0xa2bfe8a14cf10364LL, 0xa81a664bbc423001LL, 0xc24b8b70d0f89791LL,
	    0xc76c51a30654be30LL,
	0xd192e819d6ef5218LL, 0xd69906245565a910LL, 0xf40e35855771202aLL,
	    0x106aa07032bbd1b8LL,
	0x19a4c116b8d2d0c8LL, 0x1e376c085141ab53LL, 0x2748774cdf8eeb99LL,
	    0x34b0bcb5e19b48a8LL,
	0x391c0cb3c5c95a63LL, 0x4ed8aa4ae3418acbLL, 0x5b9cca4f7763e373LL,
	    0x682e6ff3d6b2b8a3LL,
	0x748f82ee5defb2fcLL, 0x78a5636f43172f60LL, 0x84c87814a1f0ab72LL,
	    0x8cc702081a6439ecLL,
	0x90befffa23631e28LL, 0xa4506cebde82bde9LL, 0xbef9a3f7b2c67915LL,
	    0xc67178f2e372532bLL,
	0xca273eceea26619cLL, 0xd186b8c721c0c207LL, 0xeada7dd6cde0eb1eLL,
	    0xf57d4f7fee6ed178LL,
	0x06f067aa72176fbaLL, 0x0a637dc5a2c898a6LL, 0x113f9804bef90daeLL,
	    0x1b710b35131c471bLL,
	0x28db77f523047d84LL, 0x32caab7b40c72493LL, 0x3c9ebe0a15c9bebcLL,
	    0x431d67c49c100d4cLL,
	0x4cc5d4becb3e42b6LL, 0x597f299cfc657e2aLL, 0x5fcb6fab3ad6faecLL,
	    0x6c44198c4a475817LL,
};

static void preproc(const uint8_t * key, uint32_t keylen,
    uint64_t * state, uint8_t var1, uint64_t var4)
{
	int i;
	uint64_t W[16];
	uint8_t ipad[16];

	uint64_t A = INIT_A;
	uint64_t B = INIT_B;
	uint64_t C = INIT_C;
	uint64_t D = INIT_D;
	uint64_t E = INIT_E;
	uint64_t F = INIT_F;
	uint64_t G = INIT_G;
	uint64_t H = INIT_H;


	for (i = 0; i < keylen; i++)
		ipad[i] = var1 ^ key[i];
	for (i = keylen; i < 16; i++)
		ipad[i] = var1;

	
	for (i = 0; i < 2; i++)
	  GET_WORD_64(W[i],ipad,i*8);

	for (i = 2; i < 16; i++)
		W[i] = var4;

	
	SHA512(A, B, C, D, E, F, G, H, W);

	state[0] = A + INIT_A;
	state[1] = B + INIT_B;
	state[2] = C + INIT_C;
	state[3] = D + INIT_D;
	state[4] = E + INIT_E;
	state[5] = F + INIT_F;
	state[6] = G + INIT_G;
	state[7] = H + INIT_H;
}

static void hmac_sha512(uint64_t * output,
    uint64_t * ipad_state, uint64_t * opad_state, const uint8_t * salt,
    int saltlen, uint8_t add)
{
	uint32_t i;
	uint64_t W[16];
	uint64_t A, B, C, D, E, F, G, H;
	uint8_t buf[128];
	uint64_t *buf64 = (uint64_t *) buf;
	i = 128 / 8;
	while (i--)
		*buf64++ = 0;
	buf64=(uint64_t*)buf;

	memcpy(buf, salt, saltlen);
	i=1;
	      buf[saltlen + 0] = (i & 0xff000000) >> 24;
	      buf[saltlen + 1] = (i & 0x00ff0000) >> 16;
	      buf[saltlen + 2] = (i & 0x0000ff00) >> 8;
	      buf[saltlen + 3] = (i & 0x000000ff) >> 0;
	
	saltlen+=4;
	buf[saltlen]=0x80;
	
	      

	PUT_WORD_64((uint64_t)((128 + saltlen) << 3),buf,120);
	
	
	
	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	for (i = 0; i < 16; i++)
		  GET_WORD_64(W[i],buf,i*8);


	SHA512(A, B, C, D, E, F, G, H, W);

	A += ipad_state[0];
	B += ipad_state[1];
	C += ipad_state[2];
	D += ipad_state[3];
	E += ipad_state[4];
	F += ipad_state[5];
	G += ipad_state[6];
	H += ipad_state[7];
	
	
	W[0]=A;
	W[1]=B;
	W[2]=C;
	W[3]=D;
	W[4]=E;
	W[5]=F;
	W[6]=G;
	W[7]=H;
	W[8] = 0x8000000000000000LL;
	W[15]=0x600;
	for(i=9;i<15;i++) W[i]=0;
	
	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];
	F = opad_state[5];
	G = opad_state[6];
	H = opad_state[7];
	
	SHA512(A, B, C, D, E, F, G, H, W);

	A += opad_state[0];
	B += opad_state[1];
	C += opad_state[2];
	D += opad_state[3];
	E += opad_state[4];
	F += opad_state[5];
	G += opad_state[6];
	H += opad_state[7];
	

	output[0] = A;
	output[1] = B;
	output[2] = C;
	output[3] = D;
	output[4] = E;
	output[5] = F;
	output[6] = G;
	output[7] = H;
}



static void big_hmac_sha512(uint64_t * input, uint32_t rounds,
    uint64_t * ipad_state, uint64_t * opad_state, uint64_t * tmp_out)
{
	int i, round;
	uint64_t W[16];
	uint64_t A, B, C, D, E, F, G, H;

	for (i = 0; i < 8; i++)
		W[i] = input[i];

	for (round = 1; round < rounds; round++) {

		A = ipad_state[0];
		B = ipad_state[1];
		C = ipad_state[2];
		D = ipad_state[3];
		E = ipad_state[4];
		F = ipad_state[5];
		G = ipad_state[6];
		H = ipad_state[7];

		W[8] = 0x8000000000000000LL;
		W[15]=0x600;
		
		for(i=9;i<15;i++) W[i]=0;
		
		SHA512(A, B, C, D, E, F, G, H, W);
		
		A += ipad_state[0];
		B += ipad_state[1];
		C += ipad_state[2];
		D += ipad_state[3];
		E += ipad_state[4];
		F += ipad_state[5];
		G += ipad_state[6];
		H += ipad_state[7];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = F;
		W[6] = G;
		W[7] = H;
		W[8] = 0x8000000000000000LL;
		W[15] = 0x600;
		
		for(i=9;i<15;i++) W[i]=0;
		
		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];
		F = opad_state[5];
		G = opad_state[6];
		H = opad_state[7];

		SHA512(A, B, C, D, E, F, G, H, W);

		A += opad_state[0];
		B += opad_state[1];
		C += opad_state[2];
		D += opad_state[3];
		E += opad_state[4];
		F += opad_state[5];
		G += opad_state[6];
		H += opad_state[7];

		W[0] = A;
		W[1] = B;
		W[2] = C;
		W[3] = D;
		W[4] = E;
		W[5] = F;
		W[6] = G;
		W[7] = H;

		tmp_out[0] ^= A;
		tmp_out[1] ^= B;
		tmp_out[2] ^= C;
		tmp_out[3] ^= D;
		tmp_out[4] ^= E;
		tmp_out[5] ^= F;
		tmp_out[6] ^= G;
		tmp_out[7] ^= H;
	}


	for (i = 0; i < 8; i++)
		tmp_out[i] = SWAP64(tmp_out[i]);
}


void grub_kernel(grub_pass * inbuffer,
    grub_crack * outbuffer)
{

	uint64_t ipad_state[8];
	uint64_t opad_state[8];
	uint64_t tmp_out[8];
	uint32_t idx,i;
	
	for(idx=0;idx<KEYS_PER_CRYPT;idx++){
		uint8_t *pass =inbuffer[idx].v;
		uint32_t passlen=inbuffer[idx].length;
		uint8_t *salt = global_salt[0].salt;
		uint32_t saltlen=global_salt[0].length;
		uint32_t rounds=global_salt[0].rounds;

	preproc(pass, passlen, ipad_state, 0x36, 0x3636363636363636LL);
#ifdef _DEBUG
	puts("ipad_state:");	
	for(i=0;i<16;i++)
		printf("%08x ",((uint32_t*)ipad_state)[i]);
	puts("");
#endif

	preproc(pass, passlen, opad_state, 0x5c, 0x5c5c5c5c5c5c5c5cLL);
#ifdef _DEBUG
	puts("opad_state:");	
	for(i=0;i<16;i++)
		printf("%08x ",((uint32_t*)opad_state)[i]);
	puts("");
#endif


	hmac_sha512(tmp_out, ipad_state, opad_state, salt, saltlen, 0x00);
#ifdef _DEBUG
	puts("hmac_sha512:");	
	for(i=0;i<16;i++)
		printf("%08x ",((uint32_t*)tmp_out)[i]);
	puts("");
#endif
	big_hmac_sha512(tmp_out, rounds, ipad_state, opad_state,tmp_out);
	for(i=0;i<8;i++)
		outbuffer[0].hash[i] = tmp_out[i];
	}
}

void cpu_grub(grub_pass * inbuffer, grub_crack * outbuffer,
    grub_salt * host_salt)
{
	size_t saltsize = sizeof(grub_salt);
	memcpy(global_salt, host_salt, saltsize);
	grub_kernel(inbuffer,outbuffer);
}


////////////////////////////////////////////////////////////////////////////////

char cracked[KEYS_PER_CRYPT];
extern void opencl_grub(grub_pass *, grub_crack *, grub_salt *);

/** Testcases generated by python passlib **/
static struct fmt_tests grub_tests[] = {	{"grub.pbkdf2.sha512.12000.4A7452.B7CF904FE1465FF7DCA05B4CC06495F7D6FEDAD9BD14A7CC97F28216161186CB626E1F3CC1825BE6865551D0A55BEC601E02F4642B391DDEE1DD499B7430E8EC", "openwall"},

{"grub.pbkdf2.sha512.12000.637261636B6D656966796F7563616E.2440B0A4344D93506B6C74783D83EF2AE9510AFBAF7D0B1A8C479E6CCDCBC649397B366856595C0033038E261CD4C79A825FC9D986F2621721A1873E43C27620","openwall"},	{"grub.pbkdf2.sha512.12000.1C0320E41C03E0FC5F0B41A8556AADF5BEF75EABB59632A6F41E638C110220444809E19CF3BE776E4D0901E0FCFFDF3B67EC7D6FED9DD3DA1BE3BCD71A8330A6.DF781E6E47F3EE8ACC0B34A41B928C6EBB9C7B4B0BB1FACA0F8175B20E524E3B0237F4EB31D38ADF94593DB746D7C0C6522FE5BD8ACE40658394EFDF08989198","John"},	{"grub.pbkdf2.sha512.12000.6F70656E77616C6C.FB9418289C4193121B24082AD72C25C2B34C5DFEF394A2B41472919028C82917EDA08C5F1F0C64A6E7075D810AB98D9A2B5460B63BF16474AE3D35049D11A497","l33t password"},	{"grub.pbkdf2.sha512.11999.F59E1362EC9D330620640CC11843C899F3BE17C2588B9192D29A532A45080120448811628CB176EEDD9BF3BE97F23E272424A4F45E8BD1BA1782B056AA55AAD5.297FE873C37BB48C49A8822D6335F2D7377DDD652645B2C2EA7838918B3EB196875AEA63C3CA85B93D84501821F1171CB5C62AD5CDDDE0DB99CA0FD2E4105DB0","password"},

/*{"grub.pbkdf2.sha512.10000.4483972AD2C52E1F590B3E2260795FDA9CA0B07B96FF492814CA9775F08C4B59CD1707F10B269E09B61B1E2D11729BCA8D62B7827B25B093EC58C4C1EAC23137.DF4FCB5DD91340D6D31E33423E4210AD47C7A4DF9FA16F401663BF288C20BF973530866178FE6D134256E4DBEFBD984B652332EED3ACAED834FEA7B73CAE851D", "password"},
*/
{NULL}
};

static int any_cracked;
static grub_pass *host_pass;                          /** plain ciphertexts **/
static grub_salt *host_salt;                          /** salt **/
static grub_crack *host_crack;                        /** cracked or no **/


static void init(struct fmt_main *pFmt)
{
        host_pass = calloc(KEYS_PER_CRYPT, sizeof(grub_pass));
        host_crack = calloc(KEYS_PER_CRYPT, sizeof(grub_crack));
        host_salt = calloc(1, sizeof(grub_salt));
        any_cracked = 1;
}

static void done(void)
{
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
        return !strncmp(ciphertext, GRUB_PREFIX, strlen(GRUB_PREFIX));
}

static void *binary(char *ciphertext)
{
	static uint8_t ret[512/8];
	int i=0;
	char *c = ciphertext;
	c+=strlen(GRUB_PREFIX);
	c++;
	c = strchr(c, '.')+1;	
	c = strchr(c, '.')+1;	
	char *p=c+128;
	assert(strlen(c)==128);//dlugosc hasha
	while(c<p){
	  ret[i++]=atoi16[tolower(c[0])]*16+atoi16[tolower(c[1])];
	 c+=2;
	}
	return ret;
}

static void *get_salt(char *ciphertext)
{
  static grub_salt salt;

  char *p,*c = ciphertext;
 	uint8_t *dest;

        int i,saltlen;

	c += strlen(GRUB_PREFIX);
        salt.rounds = atoi(c);
       c = strchr(c, '.')+1;
	if(c==NULL){
	 fprintf(stderr,"get_salt(%s) Error - probably ciphertext is broken\n",ciphertext);
	 exit(1);
	}

	p=strchr(c, '.');
	if(p==NULL){
	 fprintf(stderr,"get_salt(%s) Error - probably ciphertext is broken\n",ciphertext);
	 exit(1);
	}
	saltlen=0;
	while(c<p){
	salt.salt[saltlen++]=atoi16[tolower(c[0])]*16+atoi16[tolower(c[1])];
	 c+=2;
	}
		
	c+=1; // step over '.' between salt and hash 
	assert(strlen(c)==128);//dlugosc hasha
	salt.length=saltlen;
	p=c+128;// end of ciphertext 
	dest=(uint8_t*)salt.hash;
	i=0;
	while(c<p){
	  dest[i++]=atoi16[tolower(c[0])]*16+atoi16[tolower(c[1])];
	 c+=2;
	}
       return (void *) &salt;
}


static void set_salt(void *salt)
{
        memcpy(host_salt, salt, SALT_SIZE);
        any_cracked = 0;
}


static int crypt_all(int *pcount, struct db_salt *salt){
	int i,j,count = *pcount;
	any_cracked = 0;
	
	for(i=0;i<count;i++)
		cracked[i]=0;
        cpu_grub(host_pass,host_crack, host_salt );
        for (i = 0; i < count; i++) {
		cracked[i]=1;
		for(j=0;j<8;j++)                
			if (host_crack[i].hash[j] != host_salt->hash[j])
				cracked[i]=0;
		any_cracked|=cracked[i];
	}
	return count;
}

static int cmp_all(void *binary, int count)
{
        return any_cracked;
}

static int cmp_one(void *binary, int index)
{
        return cracked[index];
}

static int cmp_exact(char *source, int index)
{
        return 1;
}

static void set_key(char *key, int index)
{
       int saved_key_length = MIN(strlen(key), PLAINTEXT_LENGTH);
        memcpy(host_pass[index].v, key, saved_key_length);
        host_pass[index].length = saved_key_length;
}

static char *get_key(int index)
{
        static char ret[PLAINTEXT_LENGTH + 1];
        memcpy(ret, host_pass[index].v, PLAINTEXT_LENGTH);
        ret[MIN(host_pass[index].length, PLAINTEXT_LENGTH)] = 0;
        return ret;
}

static int binary_hash_0(void *binary)
{

#ifdef _DEBUG
	puts("binary");
	uint32_t i, *b = binary;
	for (i = 0; i < 16; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	return (((uint32_t *) binary)[0] & 0xf);
}

static int get_hash_0(int index)
{
#ifdef _DEBUG
	uint32_t i;
	puts("get_hash");
	for (i = 0; i < 16; i++)
		printf("%08x ", ((uint32_t*)host_crack[index].hash)[i]);
	puts("");
#endif
	return host_crack[index].hash[0] & 0xf;
}

static int get_hash_1(int index)
{
	return host_crack[index].hash[0] & 0xff;
}

static int get_hash_2(int index)
{
	return host_crack[index].hash[0] & 0xfff;
}

static int get_hash_3(int index)
{
	return host_crack[index].hash[0] & 0xffff;
}

static int get_hash_4(int index)
{
	return host_crack[index].hash[0] & 0xfffff;
}

static int get_hash_5(int index)
{
	return host_crack[index].hash[0] & 0xffffff;
}

static int get_hash_6(int index)
{
	return host_crack[index].hash[0] & 0x7ffffff;
}

struct fmt_main fmt_ukasz_pbkdf2_hmac_sha512 = {
        {
                    FORMAT_LABEL,
                    FORMAT_NAME,
                    ALGORITHM_NAME,
                    BENCHMARK_COMMENT,
                    BENCHMARK_LENGTH,
                    PLAINTEXT_LENGTH,
                    BINARY_SIZE,
		    BINARY_ALIGN,
                    SALT_SIZE,
		    SALT_ALIGN,
                    KEYS_PER_CRYPT,
                    KEYS_PER_CRYPT,
                    FMT_CASE | FMT_8_BIT,
                    grub_tests
        }, {
                    init,
	            done,
                    fmt_default_reset,
                    fmt_default_prepare,
                    valid,
                    fmt_default_split,
                    binary,
                    get_salt,
		    fmt_default_source,
                    {
                        binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
                    },
                    fmt_default_salt_hash,
                    set_salt,
                    set_key,
                    get_key,
                    fmt_default_clear_keys,
                    crypt_all,
                    {
                        get_hash_0,
			get_hash_1,
			get_hash_2,
			get_hash_3,
			get_hash_4,
			get_hash_5,
			get_hash_6
                    },
                    cmp_all,
                    cmp_one,
                    cmp_exact
           }
};

