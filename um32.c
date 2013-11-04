#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <byteswap.h>
#include <string.h>
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
	uint32_t reg[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	uint32_t pc=0;
	while(1)
	{
		uint32_t opc=code[pc];
		int a = (opc>>6)&7, b = (opc>>3)&7, c = opc&7;
		pc++;
		switch(opc>>28)
		{
			case 0:
				if(reg[c])
					reg[a] = reg[b];
				break;
			case 1:
				if(reg[b])
					reg[a] = ((uint32_t *)(uintptr_t)reg[b])[reg[c]];
				else
					reg[a] = code[reg[c]];
				break;
			case 2:
				if(reg[a])
					((uint32_t *)(uintptr_t)reg[a])[reg[b]] = reg[c];
				else
					code[reg[b]] = reg[c];
				break;
			case 3:
				reg[a] = reg[b]+reg[c];
				break;
			case 4:
				reg[a] = reg[b]*reg[c];
				break;
			case 5:
				reg[a] = reg[b]/reg[c];
				break;
			case 6:
				reg[a] = ~(reg[b]&reg[c]);
				break;
			case 7:
				exit(0);
				break;
			case 8:
				reg[b] = (uint32_t)(uintptr_t)calloc(reg[c], sizeof(uint32_t));
				break;
			case 9:
				free((uint32_t *)(uintptr_t)reg[c]);
				break;
			case 10:
				write(1, reg+c, 1);
				break;
			case 11:
			{
				reg[c] = getchar();
				break;
			}
			case 12:
				if(reg[b])
				{
					uint32_t *from = (uint32_t *)(uintptr_t)reg[b];
					code = realloc(code,malloc_usable_size(from));
					memcpy(code, from, malloc_usable_size(from));
				}
				pc = reg[c];
				break;
			case 13:
				reg[(opc>>25)&7] = opc&0x1FFFFFF;
				break;
		}
	}
}
