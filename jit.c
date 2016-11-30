#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <malloc.h>

#include <signal.h>

#include <sys/mman.h>
#include <sys/user.h>

typedef uint32_t platter_t;

struct reloc
{
	size_t offset;
	void *target;
	int abs;
};

#define ADDR_BASE ((void *)0)
#define ADDR_OFFSETS ((void *)-1)

size_t act_relocs, num_relocs = 0;
struct reloc *relocs = NULL;
uint8_t *exec_page = NULL;
size_t exec_page_act = 0, exec_page_size = 0;
platter_t *source = NULL;
size_t *offsets = NULL;

static inline void emit(size_t *ptr, uint8_t *data, size_t size, unsigned long long int value)
{
	size_t sz = size;
	while(sz--)
	{
		data[*ptr + sz] = value;
		value >>= 8;
	}
	*ptr += size;
}

static inline void emit_(size_t *ptr, uint8_t *data, uint8_t byte)
{
	data[(*ptr)++] = byte;
}

static inline void emit32(size_t *ptr, uint8_t *data, uint32_t value)
{
	*(uint32_t *)&data[*ptr] = value;
	*ptr += sizeof(uint32_t);
}

static inline void emit_imm(size_t *ptr, uint8_t *data, size_t size, void *src)
{
       uint8_t *source = src;
       while(size--)
           data[(*ptr)++] = *(source++);
}

extern void aux_poke();
extern void aux_alloc();
extern void aux_abandon();
extern void aux_jump();
extern void aux_dump();

void emit_insn(size_t *p, uint8_t *d, platter_t insn, struct reloc *relocs, size_t *num_relocs)
{
	int opcode = insn >> 28;
	int A = (insn >> 6) & 7, B = (insn >> 3) & 7, C = insn & 7;
	int immR = (insn >> 25) & 7, immV = insn & 0x1FFFFFF;
	
	//emit(p, d, 1, 0xBE); emit_imm(p, d, 4, &insn);
	//emit(p, d, 1, 0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_dump, 0}; emit(p, d, 4, 0);
	switch(opcode)
	{
	case 0:
		// test %rCd, %rCd
		emit_(p, d, 0x45); emit_(p, d, 0x85); emit_(p, d, 0xC0 | C << 3 | C);
		// cmovnz %rBd, %rAd
		emit_(p, d, 0x45); emit_(p, d, 0x0F); emit_(p, d, 0x45); emit_(p, d, 0xC0 | A << 3 | B);
		break;
	case 1:
		// mov %rBd, %eax
		emit_(p, d, 0x44); emit_(p, d, 0x89); emit_(p, d, 0xC0 | B << 3);
		// test %eax, %eax
		emit_(p, d, 0x85); emit_(p, d, 0xC0);
		// jnz . + 7
		emit_(p, d, 0x75); emit_(p, d, 0x05);
		// mov $source, %eax
		emit_(p, d, 0xB8); relocs[(*num_relocs)++] = (struct reloc){*p, source, 1}; emit32(p, d, 0);
		// mov (%eax, %rCd, 4), %rAd
		emit_(p, d, 0x67); emit_(p, d, 0x46); emit_(p, d, 0x8B); emit_(p, d, 0x04 | A << 3); emit_(p, d, 0x80 | C << 3);
		break;
	case 2:
		// mov %rAd, %eax
		emit(p, d, 3, 0x4489C0 | A << 3);
		// test %eax, %eax
		emit(p, d, 2, 0x85C0);
		// jnz . + 15
		emit(p, d, 2, 0x750d);
		// mov %rB, %rdi
		emit(p, d, 3, 0x4C89C7 | B << 3);
		// mov %rC, %rsi
		emit(p, d, 3, 0x4C89C6 | C << 3);
		// call aux_poke
		emit(p, d, 1, 0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_poke, 0}; emit(p, d, 4, 0);
		// jmp . + 7
		emit(p, d, 2, 0xEB05);
		// mov %rCd, (%eax, %rBd, 4)
		emit(p, d, 5, 0x6746890480 | C << 11 | B << 3);
		break;
	case 3:
		if(A == B)
		{
			// add %rCd, %rAd
			emit(p, d, 3, 0x4501C0 | C << 3 | A);
		}
		else if(A == C)
		{
			// add %rBd, %rAd
			emit(p, d, 3, 0x4501C0 | B << 3 | A);
		}
		else
		{
			// mov %rBd, %rAd
			emit(p, d, 3, 0x4589C0 | B << 3 | A);
			// add %rCd, %rAd
			emit(p, d, 3, 0x4501C0 | C << 3 | A);
		}
		break;
	case 4:
		// mov %rBd, %eax
		emit(p, d, 3, 0x4489C0 | B << 3);
		// mul %rCd
		emit(p, d, 3, 0x41F7E0 | C);
		// mov %eax, %rAd
		emit(p, d, 3, 0x4189C0 | A);
		break;
	case 5:
		// mov %rBd, %eax
		emit(p, d, 3, 0x4489C0 | B << 3);
		// xor %edx, %edx
		emit(p, d, 2, 0x31D2);
		// div %rCd
		emit(p, d, 3, 0x41F7F0 | C);
		// mov %eax, %rAd
		emit(p, d, 3, 0x4189C0 | A);
		break;
	case 6:
		if(A == B)
		{
			// and %rCd, %rAd
			emit(p, d, 3, 0x4521C0 | C << 3 | A);
			// not %rAd
			emit(p, d, 3, 0x41F7D0 | A);
		}
		else if(A == C)
		{
			// and %rBd, %rAd
			emit(p, d, 3, 0x4521C0 | B << 3 | A);
			// not %rAd
			emit(p, d, 3, 0x41F7D0 | A);
		}
		else
		{
			// mov %rBd, %rAd
			emit(p, d, 3, 0x4589C0 | B << 3 | A);
			// and %rCd, %rAd
			emit(p, d, 3, 0x4521C0 | C << 3 | A);
			// not %rAd
			emit(p, d, 3, 0x41F7D0 | A);
		}
		break;
	case 7:
		// ret
		emit(p, d, 1, 0xC3);
		break;
	case 8:
		// mov %rC, %rdi
		emit(p, d, 3, 0x4C89C7 | C << 3);
		// callq aux_alloc
		emit(p, d, 1, 0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_alloc, 0}; emit(p, d, 4, 0);
		// mov %eax, %rBd
		emit(p, d, 3, 0x4189C0 | B);
		break;
	case 9:
		// mov %rC, %rdi
		emit(p, d, 3, 0x4C89C7 | C << 3);
		// callq aux_abandon
		emit(p, d, 1, 0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_abandon, 0}; emit(p, d, 4, 0);
		break;
	case 10:
		// mov %rC, %rdi
		emit(p, d, 3, 0x4C89C7 | C << 3);
		// pushq %r8
		emit(p, d, 2, 0x4150);
		// pushq %r9
		emit(p, d, 2, 0x4151);
		// pushq %r10
		emit(p, d, 2, 0x4152);
		// pushq %r11
		emit(p, d, 2, 0x4153);
		// callq putchar
		emit(p, d, 1, 0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, putchar, 0}; emit(p, d, 4, 0);
		// popq %r11
		emit(p, d, 2, 0x415B);
		// popq %r10
		emit(p, d, 2, 0x415A);
		// popq %r9
		emit(p, d, 2, 0x4159);
		// popq %r8
		emit(p, d, 2, 0x4158);
		break;
	case 11:
		// pushq %r8
		emit(p, d, 2, 0x4150);
		// pushq %r9
		emit(p, d, 2, 0x4151);
		// pushq %r10
		emit(p, d, 2, 0x4152);
		// pushq %r11
		emit(p, d, 2, 0x4153);
		// callq getchar
		emit(p, d, 1, 0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, getchar, 0}; emit(p, d, 4, 0);
		// popq %r11
		emit(p, d, 2, 0x415B);
		// popq %r10
		emit(p, d, 2, 0x415A);
		// popq %r9
		emit(p, d, 2, 0x4159);
		// popq %r8
		emit(p, d, 2, 0x4158);
		// mov %eax, %rCd
		emit(p, d, 3, 0x4989C0 | C);
		break;
	case 12:
		// test %rBd, %rBd
		emit(p, d, 3, 0x4585C0 | B << 3 | B);
		// jz . + 13
		emit(p, d, 2, 0x740B);
		// mov %rB, %rdi
		emit(p, d, 3, 0x4C89C7 | B << 3);
		// mov %rC, %rsi
		emit(p, d, 3, 0x4C89C6 | C << 3);
		// jmp aux_jump;
		emit(p, d, 1, 0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_jump, 0}; emit(p, d, 4, 0);
		// mov offsets(, %rC, 4), %eax
		emit(p, d, 4, 0x428B04C5 | C << 3); relocs[(*num_relocs)++] = (struct reloc){*p, ADDR_OFFSETS, 1}; emit(p, d, 4, 0);
		// lea base(%rax)
		emit(p, d, 3, 0x488D80); relocs[(*num_relocs)++] = (struct reloc){*p, ADDR_BASE, 1}; emit(p, d, 4, 0);
		// jmp *%rax
		emit(p, d, 2, 0xFFE0);
		break;
	case 13:
		// mov $IMM, %rAd
		emit(p, d, 2, 0x41B8 | immR); emit_imm(p, d, 4, &immV);
		break;
	default:
		emit(p, d, 2, 0x0F0D);
		break;
	}
	emit(p, d, 4, 0x0F1F0425); emit_imm(p, d, 4, &insn);
}

asm(
	".section .text\n"
	".global aux_alloc\n"
	"aux_alloc:\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"call aux_c_alloc\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"ret\n"

	".global aux_abandon\n"
	"aux_abandon:\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"call aux_c_abandon\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"ret\n"

	".global aux_poke\n"
	"aux_poke:\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"call aux_c_poke\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"ret\n"

	".global aux_jump\n"
	"aux_jump:\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"call aux_c_jump\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"mov %rax, (%rsp)\n"
	"ret\n"

	".global aux_dump\n"
	"aux_dump:\n"
	"push %r15\n"
	"push %r14\n"
	"push %r13\n"
	"push %r12\n"
	"push %r11\n"
	"push %r10\n"
	"push %r9\n"
	"push %r8\n"
	"mov %rsp, %rdi\n"
	"call aux_c_dump\n"
	"pop %r8\n"
	"pop %r9\n"
	"pop %r10\n"
	"pop %r11\n"
	"pop %r12\n"
	"pop %r13\n"
	"pop %r14\n"
	"pop %r15\n"
	"ret\n"
);

void *exec_allocate(size_t size)
{
	void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if(addr == (void *)-1)
	{
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	return addr;
}

void exec_free(void *old, size_t size)
{
	if(munmap(old, size))
	{
		perror("munmap");
		exit(EXIT_FAILURE);
	}
}

void *exec_reallocate(void *old, size_t oldsz, size_t newsz)
{
	void *addr = mremap(old, oldsz, newsz, 0);
	if(addr == (void *)-1)
	{
		if(errno == ENOMEM)
		{
			void *addr = exec_allocate(newsz);
			memcpy(addr, old, oldsz);
			exec_free(old, oldsz);
			return addr;
		}
		perror("mremap");
		exit(EXIT_FAILURE);
	}
	return addr;
}

void satisfy_reloc(struct reloc *reloc)
{
	void *addr = exec_page + reloc->offset;
	void *location = reloc->target;
	if(location == ADDR_BASE)
		location = exec_page;
	else if(location == ADDR_OFFSETS)
		location = offsets;
	*(uint32_t *)addr = (intptr_t)location - (reloc->abs ? 0 : (intptr_t)(addr + sizeof(uint32_t)));
}

void aux_c_dump(long int regs[8], platter_t insn)
{
	int i;
	if((insn >> 28) == 13)
		fprintf(stderr, "%08x(%2d %2d      ):  ", insn, insn >> 28, (insn >> 25) & 7);
	else
		fprintf(stderr, "%08x(%2d %2d %2d %2d):  ", insn, insn >> 28, (insn >> 6) & 7, (insn >> 3) & 7, insn & 7);
	for(i = 0; i < 8; i++)
		fprintf(stderr, "r%d: %08lx ", i, regs[i]);
	fprintf(stderr, "\n");
}

void *aux_c_alloc(size_t size)
{
	void *addr = calloc(size * sizeof(platter_t) + sizeof(size_t), 1);
	*(size_t *)addr = size;
	return addr + sizeof(size_t);
}

void aux_c_abandon(void *ptr)
{
	size_t *addr = (size_t *)ptr - 1;
	free(addr);
}

void aux_c_poke(size_t offset, platter_t value)
{
	source[offset] = value;
	size_t tmp = 0;
	emit(&tmp, &exec_page[offsets[offset]], 2, 0xFFD1);
}

void jit_array(platter_t *array, size_t size)
{
	exec_page_act = PAGE_SIZE;
	exec_page = exec_allocate(exec_page_act);

	source = malloc(size * sizeof(platter_t));
	memcpy(source, array, size * sizeof(platter_t));

	offsets = malloc((size + 1) * sizeof(size_t));

	size_t i;
	size_t offset = 0;
	for(i = 0; i < size; i++)
	{
		if(num_relocs + 8 > act_relocs)
		{
			act_relocs += 16;
			relocs = realloc(relocs, act_relocs * sizeof(struct reloc));
		}

		if(offset + 64 > exec_page_act)
		{
			exec_page = exec_reallocate(exec_page, exec_page_act, exec_page_act + PAGE_SIZE);
			exec_page_act += PAGE_SIZE;
		}

		offsets[i] = offset;

		emit_insn(&offset, exec_page, array[i], relocs, &num_relocs);
	}
	offsets[size] = offset;
	exec_page_size = offset;

	for(i = 0; i < num_relocs; i++)
		satisfy_reloc(&relocs[i]);

}

void *aux_c_jump(void *array, size_t offset)
{
	free(relocs);
	act_relocs = num_relocs = 0;
	relocs = NULL;
	exec_free(exec_page, exec_page_act);
	exec_page = NULL;
	exec_page_act = exec_page_size = 0;
	free(source);
	source = NULL;
	free(offsets);
	offsets = NULL;
	jit_array(array, ((size_t *)array)[-1]);
	return exec_page + offsets[offset];
}

void sighandler(int sig)
{
	exit(0);
}

int main(int argc, char **argv)
{
	signal(SIGQUIT, sighandler);

	if(argc < 2)
		exit(EXIT_SUCCESS);
	FILE *f = fopen(argv[1], "rb");
	fseek(f, 0, SEEK_END);
	size_t size = ftell(f) / sizeof(platter_t);
	fseek(f, 0, SEEK_SET);
	platter_t *source = calloc(size, sizeof(platter_t));
	size_t i = 0;
	while(i < size)
		i += fread(source + i, sizeof(platter_t), size - i, f);
	for(i = 0; i < size; i++)
	{
		platter_t x = source[i];
		source[i] = ((x & 0xFF000000) >> 24) | ((x & 0xFF0000) >> 8) | ((x & 0xFF00) << 8) | ((x & 0xFF) << 24);
	}

	mallopt(M_MMAP_MAX, 0);

	jit_array(source, size);
	free(source);

	asm volatile (
		"xor %%r8, %%r8\n"
		"xor %%r9, %%r9\n"
		"xor %%r10, %%r10\n"
		"xor %%r11, %%r11\n"
		"xor %%r12, %%r12\n"
		"xor %%r13, %%r13\n"
		"xor %%r14, %%r14\n"
		"xor %%r15, %%r15\n"
		"enter_bytecode:\n"
		"call *%0\n"
		:: "o"(exec_page) : "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	);
}
