um32: Makefile um32.c
	cc -m32 -O3 -o um32 um32.c
um32asm: Makefile um32asm.S
	cc -m32 -o um32asm um32asm.S
