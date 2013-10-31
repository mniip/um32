#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <byteswap.h>
#include <string.h>
#ifdef DEBUG
#	define printf(...) fprintf(stderr,__VA_ARGS__)
#else
#	define printf(...)
#endif
int main(int argc, const char *argv[])
{
	if(argc<2)
		exit(0);
	int fd = open(argv[1], O_RDONLY);
	int sz = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	uint32_t *code = malloc(sz);
	int l=0;
	while(l<sz)
		l += read(fd, code+l, sz-l);
	for(l=0;l<sz/sizeof(uint32_t);l++)
		code[l]=__bswap_32(code[l]);
	void* orig_code = code;
	uint32_t reg[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	uint32_t pc=0;
	int n=0;
	while(1)
	{
		uint32_t opc=code[pc];
		int i;
		if(!(n%32))
		{
			for(i=0;i<8;i++)
				printf("   r%d   |",i);
			printf("   array:finger   |\n");
		}
		n++;
		for(i=0;i<8;i++)
			printf("%08x ",reg[i]);
		char op = opc>>28, a = (opc>>6)&7, b = (opc>>3)&7, c = opc&7;
		printf("%08x:%08x | ",(uintptr_t)(code==orig_code?0:code),pc);
		pc++;
		switch(op)
		{
			case 0:
				printf("r%d:=r%d if r%d\n",a,b,c);
				if(reg[c])
					reg[a] = reg[b];
				break;
			case 1:
				printf("r%d:=r%d[r%d]\n",a,b,c);
				if(reg[b])
					reg[a] = ((uint32_t *)(uintptr_t)reg[b])[reg[c]];
				else
					reg[a] = code[reg[c]];
				break;
			case 2:
				printf("r%d[r%d]:=r%d\n",a,b,c);
				if(reg[a])
					((uint32_t *)(uintptr_t)reg[a])[reg[b]] = reg[c];
				else
					code[reg[b]] = reg[c];
				break;
			case 3:
				printf("r%d:=r%d+r%d\n",a,b,c);
				reg[a] = reg[b]+reg[c];
				break;
			case 4:
				printf("r%d:=r%d*r%d\n",a,b,c);
				reg[a] = reg[b]*reg[c];
				break;
			case 5:
				printf("r%d:=r%d/r%d\n",a,b,c);
				reg[a] = reg[b]/reg[c];
				break;
			case 6:
				printf("r%d:=r%d~&r%d\n",a,b,c);
				reg[a] = ~(reg[b]&reg[c]);
				break;
			case 7:
				printf("exit\n");
				exit(0);
				break;
			case 8:
				printf("r%d:=malloc(r%d)\n",b,c);
				printf("[MEM] allocating %08x plates\n",reg[c]);
				reg[b] = (uint32_t)(uintptr_t)calloc(reg[c], sizeof(uint32_t));
				printf("[MEM]   at %08x\n",reg[b]);
				break;
			case 9:
				printf("free(r%d)\n",c);
				free((uint32_t *)(uintptr_t)reg[c]);
				printf("[MEM] freeing %08x\n",reg[c]);
				break;
			case 10:
				printf("putchar(r%d) '%c'\n",c,reg[c]);
				putchar(reg[c]);
				break;
			case 11:
			{
				printf("r%d:=read()\n",c);
				char i;
				read(0, &i, 1);
				reg[c] = i;
				break;
			}
			case 12:
				printf("jump r%d[r%d]\n",b,c);
				if(reg[b])
				{
					uint32_t *from = (uint32_t *)(uintptr_t)reg[b];
					code = realloc(code,malloc_usable_size(from));
					memcpy(code, from, malloc_usable_size(from));
				}
				pc = reg[c];
				break;
			case 13:
				printf("r%d:=0x%07x\n",(opc>>25)&7,opc&0x1FFFFFF);
				reg[(opc>>25)&7] = opc&0x1FFFFFF;
				break;
		}
	}
}
