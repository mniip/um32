umjitv2: Makefile umjitv2.c
	cc -m64 -O3 -o umjitv2 umjitv2.c
umjit: Makefile umjit.c
	cc -m64 -O3 -o umjit umjit.c
um32: Makefile um32.c
	cc -m32 -O3 -o um32 um32.c
um32asm: Makefile um32asm.S
	cc -m32 -o um32asm um32asm.S
