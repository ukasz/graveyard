/*
	This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
	and it is hereby released to the general public under the following terms:
	Redistribution and use in source and binary forms, with or without modification, are permitted.

	Name: JtR PBKDF2 HMAC SHA256 format
	Status: working, archive

	Tested on 4770k:
	../run/john -test -format=pbkdf2-sha256
	Benchmarking: pbkdf2-sha256, CPU generic, rounds=12000 [PBKDF2-HMAC-SHA256]... DONE
	Raw:	63.1 c/s real, 63.5 c/s virtual
*/
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "misc.h"
#include "arch.h"
#include "common.h"
#include "base64.h"
#include "formats.h"

#define FORMAT_LABEL		"pbkdf2-sha256"
#define FORMAT_NAME		"CPU generic"
#define ALGORITHM_NAME		"PBKDF2-HMAC-SHA256"

#define BENCHMARK_COMMENT	", rounds=12000"
#define BENCHMARK_LENGTH	-1
#define KEYS_PER_CRYPT		1

#define BINARY_ALIGN		4
#define SALT_ALIGN		1

#define uint8_t			unsigned char
#define uint16_t		unsigned short
#define uint32_t		unsigned int

#define PLAINTEXT_LENGTH	55
#define BINARY_SIZE		32
#define	SALT_SIZE		sizeof(salt_t)

#define FMT_PREFIX		"$pbkdf2-sha256$"

#define MIN(a,b)		(((a)<(b))?(a):(b))
#define MAX(a,b)		(((a)>(b))?(a):(b))

typedef struct {
	uint8_t length;
	uint8_t v[PLAINTEXT_LENGTH];//TODO should be grater
} pass_t;

typedef struct {
  uint32_t hash[8]; /** 256 bits **/
} crack_t;

typedef struct {
	uint8_t length;
	uint8_t salt[64];
	uint32_t rounds;  /** 12000 by default **/
	uint32_t hash[8]; /** 256 bits **/
} salt_t;


////////////////////////////////////////////////////////////////////////////////
#define SWAP(n) \
            (((n) << 24)               | (((n) & 0xff00) << 8) |     \
            (((n) >> 8) & 0xff00)      | ((n) >> 24))

#define ror(x,n) ((x >> n) | (x << (32-n)))
#define Ch(x,y,z) ( z ^ (x & ( y ^ z)) )
#define Maj(x,y,z) ( (x & y) | (z & (x | y)) )
#define Sigma0(x) ((ror(x,2))  ^ (ror(x,13)) ^ (ror(x,22)))
#define Sigma1(x) ((ror(x,6))  ^ (ror(x,11)) ^ (ror(x,25)))
#define sigma0(x) ((ror(x,7))  ^ (ror(x,18)) ^(x>>3))
#define sigma1(x) ((ror(x,17)) ^ (ror(x,19)) ^(x>>10))


#define SHA256_DIGEST_LENGTH	32

#define SHA256(a, b, c, d, e, f, g, h, w) \
	{ \
	uint32_t t1,t2,i;\
    for (i = 0; i < 16; i++) {\
        t1 = k[i] + w[i] + h + Sigma1(e) + Ch(e, f, g);\
        t2 = Maj(a, b, c) + Sigma0(a);\
        h = g;\
        g = f;\
        f = e;\
        e = d + t1;\
        d = c;\
        c = b;\
        b = a;\
        a = t1 + t2;\
    }\
    for (i = 16; i < 64; i++) {\
        w[i & 15] = sigma1(w[(i - 2) & 15]) + sigma0(w[(i - 15) & 15]) + w[(i - 16) & 15] + w[(i - 7) & 15];\
        t1 = k[i] + w[i & 15] + h + Sigma1(e) + Ch(e, f, g);\
        t2 = Maj(a, b, c) + Sigma0(a);\
        h = g;\
        g = f;\
        f = e;\
        e = d + t1;\
        d = c;\
        c = b;\
        b = a;\
        a = t1 + t2;\
	}}
	
#define GET_WORD_32_BE(n,b,i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
        | ( (unsigned long) (b)[(i) + 1] << 16 )        \
        | ( (unsigned long) (b)[(i) + 2] <<  8 )        \
        | ( (unsigned long) (b)[(i) + 3]       );       \
}

#define PUT_WORD_32_BE(n,b,i)                           \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
static salt_t global_salt[1];
static const uint32_t h[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
static const uint32_t k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


static void preproc(const uint8_t * key, uint32_t keylen, uint32_t * state, 
	uint8_t var1, uint32_t padding)
{
	int i;
	uint32_t W[16];
//check whether immediates are faster
	uint32_t A = h[0];
	uint32_t B = h[1];
	uint32_t C = h[2];
	uint32_t D = h[3];
	uint32_t E = h[4];
	uint32_t F = h[5];
	uint32_t G = h[6];
	uint32_t H = h[7];
//TODO define for no byte addressable store
#define XORCHAR_BE(buf, index, val) ((unsigned char*)(buf))[(index) ^ 3] ^= (val)


	for (i = 0; i < 16; i++)
		W[i] = padding;

	for (i = 0; i < keylen; i++)
		XORCHAR_BE(W, i, key[i]);


	
	SHA256(A, B, C, D, E, F, G, H, W);

	state[0] = A + h[0];
	state[1] = B + h[1];
	state[2] = C + h[2];
	state[3] = D + h[3];
	state[4] = E + h[4];
	state[5] = F + h[5];
	state[6] = G + h[6];
	state[7] = H + h[7];
}

static void hmac_sha256(uint32_t * output, uint32_t * ipad_state, 
	uint32_t * opad_state, const uint8_t * salt, int saltlen)
{
	uint32_t i;
	uint32_t W[16];
	uint32_t A, B, C, D, E, F, G, H;
	uint8_t buf[64];
	uint32_t *buf32 = (uint32_t *) buf;
	i = 64 / 4;
	while (i--)
		*buf32++ = 0;

	memcpy(buf, salt, saltlen);
	buf[saltlen + 3] = 0x1;
	buf[saltlen + 4] = 0x80;	      

	PUT_WORD_32_BE((uint32_t)((64 + saltlen + 4) << 3), buf, 60);

	A = ipad_state[0];
	B = ipad_state[1];
	C = ipad_state[2];
	D = ipad_state[3];
	E = ipad_state[4];
	F = ipad_state[5];
	G = ipad_state[6];
	H = ipad_state[7];

	for (i = 0; i < 16; i++)
		  GET_WORD_32_BE(W[i], buf, i * 4);
	
	SHA256(A, B, C, D, E, F, G, H, W);

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
	W[8] = 0x80000000;
	W[15] = 0x300;
	for(i=9;i<15;i++) W[i]=0;
	
	A = opad_state[0];
	B = opad_state[1];
	C = opad_state[2];
	D = opad_state[3];
	E = opad_state[4];
	F = opad_state[5];
	G = opad_state[6];
	H = opad_state[7];
	
	SHA256(A, B, C, D, E, F, G, H, W);

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



static void big_hmac_sha256(uint32_t * input, uint32_t rounds,
	uint32_t * ipad_state, uint32_t * opad_state, uint32_t * tmp_out)
{
	int i, round;
	uint32_t W[16];
	uint32_t A, B, C, D, E, F, G, H;

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

		W[8] = 0x80000000;
		W[15] = 0x300;
		
		for(i=9;i<15;i++) W[i]=0;
		
		SHA256(A, B, C, D, E, F, G, H, W);
		
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
		W[8] = 0x80000000;
		W[15] = 0x300;
		
		for(i=9;i<15;i++) W[i]=0;
		
		A = opad_state[0];
		B = opad_state[1];
		C = opad_state[2];
		D = opad_state[3];
		E = opad_state[4];
		F = opad_state[5];
		G = opad_state[6];
		H = opad_state[7];

		SHA256(A, B, C, D, E, F, G, H, W);

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
		tmp_out[i] = SWAP(tmp_out[i]);
}


static void kernel(pass_t * inbuffer, crack_t * outbuffer)
{

	uint32_t ipad_state[8];
	uint32_t opad_state[8];
	uint32_t tmp_out[8];
	uint32_t idx,i;
	
	for(idx=0;idx<KEYS_PER_CRYPT;idx++){
		uint8_t *pass =inbuffer[idx].v;
		uint32_t passlen=inbuffer[idx].length;
		uint8_t *salt = global_salt[0].salt;
		uint32_t saltlen=global_salt[0].length;
		uint32_t rounds=global_salt[0].rounds;

	preproc(pass, passlen, ipad_state, 0x36, 0x36363636);
#ifdef _DEBUG
	puts("ipad_state:");	
	for(i=0;i<8;i++)
		printf("%08x ",((uint32_t*)ipad_state)[i]);
	puts("");
#endif

	preproc(pass, passlen, opad_state, 0x5c, 0x5c5c5c5c);
#ifdef _DEBUG
	puts("opad_state:");	
	for(i=0;i<8;i++)
		printf("%08x ",((uint32_t*)opad_state)[i]);
	puts("");
#endif


	hmac_sha256(tmp_out, ipad_state, opad_state, salt, saltlen);
#ifdef _DEBUG
	puts("hmac_sha256:");	
	for(i=0;i<8;i++)
		printf("%08x ",((uint32_t*)tmp_out)[i]);
	puts("");
#endif
	big_hmac_sha256(tmp_out, rounds, ipad_state, opad_state,tmp_out);
	for(i=0;i<8;i++)
		outbuffer[0].hash[i] = tmp_out[i];
	}
}

static void cpu_kernel(pass_t * inbuffer, crack_t * outbuffer, salt_t * host_salt)
{
	size_t saltsize = sizeof(salt_t);
	memcpy(global_salt, host_salt, saltsize);
	kernel(inbuffer,outbuffer);
}

char cracked[KEYS_PER_CRYPT];

static struct fmt_tests tests[] = {
/*
	Testcases generated by passlib, format: $pbkdf2-256$rounds$salt$checksum 
	salt and checksum are encoded in "adapted base64"
*/
{"$pbkdf2-sha256$12000$2NtbSwkhRChF6D3nvJfSGg$OEWLc4keep8Vx3S/WnXgsfalb9q0RQdS1s05LfalSG4",""},
{"$pbkdf2-sha256$12000$fK8VAoDQuvees5ayVkpp7Q$xfzKAoBR/Iaa68tjn.O8KfGxV.zdidcqEeDoTFvDz2A","1"},
{"$pbkdf2-sha256$12000$GoMQYsxZ6/0fo5QyhtAaAw$xQ9L6toKn0q245SIZKoYjCu/Fy15hwGme9.08hBde1w","12"},
{"$pbkdf2-sha256$12000$6r3XWgvh/D/HeA/hXAshJA$11YY39OaSkJuwb.ONKVy5ebCZ00i5f8Qpcgwfe3d5kY","123"},
{"$pbkdf2-sha256$12000$09q711rLmbMWYgwBIGRMqQ$kHdAHlnQ1i1FHKBCPLV0sA20ai2xtYA1Ev8ODfIkiQg","1234"},
{"$pbkdf2-sha256$12000$Nebce08pJcT43zuHUMo5Rw$bMW/EsVqy8tMaDecFwuZNEPVfQbXBclwN78okLrxJoA","openwall"},
{"$pbkdf2-sha256$12000$mtP6/39PSQlhzBmDsJZS6g$zUXxf/9XBGrkedXVwhpC9wLLwwKSvHX39QRz7MeojYE","password"},
{"$pbkdf2-sha256$12000$35tzjhGi9J5TSilF6L0XAg$MiJA1gPN1nkuaKPVzSJMUL7ucH4bWIQetzX/JrXRYpw","pbkdf2-sha256"},
{"$pbkdf2-sha256$12000$sxbCeE8pxVjL2ds7hxBizA$uIiwKdo9DbPiiaLi1y3Ljv.r9G1tzxLRdlkD1uIOwKM"," 15 characters "},
{"$pbkdf2-sha256$12000$CUGI8V7rHeP8nzMmhJDyXg$qjq3rBcsUgahqSO/W4B1bvsuWnrmmC4IW8WKMc5bKYE"," 16 characters__"},
{"$pbkdf2-sha256$12000$FmIM4VxLaY1xLuWc8z6n1A$OVe6U1d5dJzYFKlJsZrW1NzUrfgiTpb9R5cAfn96WCk"," 20 characters______"},
{"$pbkdf2-sha256$12000$fA8BAMAY41wrRQihdO4dow$I9BSCuV6UjG55LktTKbV.bIXtyqKKNvT3uL7JQwMLp8"," 24 characters______1234"},
{"$pbkdf2-sha256$12000$/j8npJTSOmdMKcWYszYGgA$PbhiSNRzrELfAavXEsLI1FfitlVjv9NIB.jU1HHRdC8"," 28 characters______12345678"},
{"$pbkdf2-sha256$12000$xfj/f6/1PkcIoXROCeE8Bw$ci.FEcPOKKKhX5b3JwzSDo6TGuYjgj1jKfCTZ9UpDM0"," 32 characters______123456789012"},
{"$pbkdf2-sha256$12000$6f3fW8tZq7WWUmptzfmfEw$GDm/yhq1TnNR1MVGy73UngeOg9QJ7DtW4BnmV2F065s"," 40 characters______12345678901234567890"},
{"$pbkdf2-sha256$12000$dU5p7T2ndM7535tzjpGyVg$ILbppLkipmonlfH1I2W3/vFMyr2xvCI8QhksH8DWn/M"," 55 characters______________________________________end"},
{NULL}
};

static int any_cracked;
static pass_t *host_pass;                          /** plain ciphertexts **/
static salt_t *host_salt;                          /** salt **/
static crack_t *host_crack;                        /** cracked or no **/


static void init(struct fmt_main *pFmt)
{
        host_pass = calloc(KEYS_PER_CRYPT, sizeof(pass_t));
        host_crack = calloc(KEYS_PER_CRYPT, sizeof(crack_t));
        host_salt = calloc(1, sizeof(salt_t));
        any_cracked = 1;
}

static void done(void)
{
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
        return !strncmp(ciphertext, FMT_PREFIX, strlen(FMT_PREFIX));
}

/* adapted base64 encoding used by passlib - s/./+/ and trim padding */
static void abase64_decode(const char *in, int length, char *out)
{
	int i;
	static char hash[44+1];
#ifdef DEBUG
	assert(length <= 44);
	assert(length % 4 != 1);
#endif
	memset(hash, '=', 44);
	memcpy(hash, in, length);
	for(i=0; i < length; i++)
		if(hash[i] == '.')
			hash[i] = '+';
	switch(length % 4)
	{
		case 2: length+=2; break;
		case 3: length++; break;
	}	
	hash[length]=0;
	base64_decode(hash, length, out);
}

static void *passlib_binary(char *ciphertext)
{
	static char ret[256/8];
	char *c = ciphertext;
	c += strlen(FMT_PREFIX) + 1;
	c = strchr(c, '$')+1;	
	c = strchr(c, '$')+1;
#ifdef DEBUG
	assert(strlen(c)==43);//hash length
#endif
	abase64_decode(c,43,ret);	
	return ret;
}

static void *binary(char *ciphertext)
{
	return passlib_binary(ciphertext);
}

static void *get_salt(char *ciphertext)
{

	static salt_t salt;
	char *p,*c=ciphertext, *oc;
	c += strlen(FMT_PREFIX);
        salt.rounds = atoi(c);

        c = strchr(c, '$')+1;
	p=strchr(c, '$');
	salt.length=0;
	oc=c;
	while(c++<p) salt.length++;

	abase64_decode(oc,salt.length,(char*)salt.salt);
	salt.length=ceil(salt.length*3/4);
	memcpy(salt.hash, (char*) binary(ciphertext), BINARY_SIZE);
       return (void *) &salt;
}


static void set_salt(void *salt)
{
        memcpy(host_salt, salt, SALT_SIZE);
        any_cracked = 0;
}


static int crypt_all(int *pcount, struct db_salt *salt){
	int i, j, count;
	count = *pcount;
	any_cracked = 0;
	
	for(i=0;i<count;i++)
		cracked[i]=0;
        cpu_kernel(host_pass,host_crack, host_salt );
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
	int length = MIN(strlen(key), PLAINTEXT_LENGTH);
	memcpy(host_pass[index].v, key, length);
	host_pass[index].length = length;
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

#ifdef DEBUG
	puts("binary:");
	uint32_t i, *b = binary;
	for (i = 0; i < 8; i++)
		printf("%08x ", b[i]);
	puts("");
#endif
	return (((uint32_t *) binary)[0] & 0xf);
}

static int get_hash_0(int index)
{
#ifdef DEBUG
	uint32_t i;
	puts("get_hash:");
	for (i = 0; i < 8; i++)
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

struct fmt_main fmt_ukasz_pbkdf2_hmac_sha256 = {
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
                    tests
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




















