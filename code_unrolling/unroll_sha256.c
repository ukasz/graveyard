/*
	This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
	and it is hereby released to the general public under the following terms:
	Redistribution and use in source and binary forms, with or without modification, are permitted.

	Name: Code for unrolling sha256 loop
	Status: working, archive
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SIZE (8*64)
char t[]="ABCDEFGH";
char b[SIZE];
int main() {
	int i;
	puts("ROUND_B(A,B,C,D,E,F,G,H,k[16],W[0],  W[14],W[1],W[0],W[9])");
	puts("");
	char *s=b;
	for(i=0;i<64;i++){
		memcpy(s,t,8);
		s+=8;
	}
	s=b;
	#define A *(s+0)
	#define B *(s+1)
	#define C *(s+2)
	#define D *(s+3)
	#define E *(s+4)
	#define F *(s+5)
	#define G *(s+6)
	#define H *(s+7)

	for(i=16;i<64;i++){
		printf("ROUND_B(%c,%c,%c,%c,%c,%c,%c,%c,k[%d],W[%d],  W[%d],W[%d],W[%d],W[%d])\n",A,B,C,D,E,F,G,H,  i, i&15, (i-2)&15,  (i-15)&15,(i-16)&15,(i-7)&15);
		s+=7;
	} 
	return 0;
}

