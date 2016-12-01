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
size_t source_size = 0;
void **offsets = NULL;

extern void aux_poke();
extern void aux_alloc();
extern void aux_abandon();
extern void aux_jump();
extern void aux_dump();
extern void aux_putchar();
extern void aux_getchar();

void emit_insn(size_t *p, uint8_t *d, platter_t insn, struct reloc *relocs, size_t *num_relocs)
{
	int opcode = insn >> 28;
	int A = (insn >> 6) & 7, B = (insn >> 3) & 7, C = insn & 7;
	int immR = (insn >> 25) & 7, immV = insn & 0x1FFFFFF;

#define EMIT(v) (d[(*p)++] = (v))
#define EMIT32(v) (*(uint32_t *)&d[*p] = (v), *p += sizeof(uint32_t))
	
	//EMIT(0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_dump, 0}; EMIT32(0);
	switch(opcode)
	{
	case 0:
		// test %rCd, %rCd
		EMIT(0x45); EMIT(0x85); EMIT(0xC0 | C << 3 | C);
		// cmovnz %rBd, %rAd
		EMIT(0x45); EMIT(0x0F); EMIT(0x45); EMIT(0xC0 | A << 3 | B);
		break;
	case 1:
		// mov %rBd, %eax
		EMIT(0x44); EMIT(0x89); EMIT(0xC0 | B << 3);
		// test %eax, %eax
		EMIT(0x85); EMIT(0xC0);
		// jnz . + 7
		EMIT(0x75); EMIT(0x05);
		// mov $source, %eax
		EMIT(0xB8); relocs[(*num_relocs)++] = (struct reloc){*p, source, 1}; EMIT32(0);
		// mov (%eax, %rCd, 4), %rAd
		EMIT(0x67); EMIT(0x46); EMIT(0x8B); EMIT(0x04 | A << 3); EMIT(0x80 | C << 3);
		break;
	case 2:
		// mov %rAd, %eax
		EMIT(0x44); EMIT(0x89); EMIT(0xC0 | A << 3);
		// test %eax, %eax
		EMIT(0x85); EMIT(0xC0);
		// jnz . + 15
		EMIT(0x75); EMIT(0x0D);
		// mov %rB, %rdi
		EMIT(0x4C); EMIT(0x89); EMIT(0xC7 | B << 3);
		// mov %rC, %rsi
		EMIT(0x4C); EMIT(0x89); EMIT(0xC6 | C << 3);
		// call aux_poke
		EMIT(0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_poke, 0}; EMIT32(0);
		// jmp . + 7
		EMIT(0xEB); EMIT(0x05);
		// mov %rCd, (%eax, %rBd, 4)
		EMIT(0x67); EMIT(0x46); EMIT(0x89); EMIT(0x04 | C << 3); EMIT(0x80 | B << 3);
		break;
	case 3:
		if(A == B)
		{
			// add %rCd, %rAd
			EMIT(0x45); EMIT(0x01); EMIT(0xC0 | C << 3 | A);
		}
		else if(A == C)
		{
			// add %rBd, %rAd
			EMIT(0x45); EMIT(0x01); EMIT(0xC0 | B << 3 | A);
		}
		else
		{
			// mov %rBd, %rAd
			EMIT(0x45); EMIT(0x89); EMIT(0xC0 | B << 3 | A);
			// add %rCd, %rAd
			EMIT(0x45); EMIT(0x01); EMIT(0xC0 | C << 3 | A);
		}
		break;
	case 4:
		// mov %rBd, %eax
		EMIT(0x44); EMIT(0x89); EMIT(0xC0 | B << 3);
		// mul %rCd
		EMIT(0x41); EMIT(0xF7); EMIT(0xE0 | C);
		// mov %eax, %rAd
		EMIT(0x41); EMIT(0x89); EMIT(0xC0 | A);
		break;
	case 5:
		// mov %rBd, %eax
		EMIT(0x44); EMIT(0x89); EMIT(0xC0 | B << 3);
		// xor %edx, %edx
		EMIT(0x31); EMIT(0xD2);
		// div %rCd
		EMIT(0x41); EMIT(0xF7); EMIT(0xF0 | C);
		// mov %eax, %rAd
		EMIT(0x41); EMIT(0x89); EMIT(0xC0 | A);
		break;
	case 6:
		if(A == B && A == C)
		{
			// not %rAd
			EMIT(0x41); EMIT(0xF7); EMIT(0xD0 | A);
		}
		else if(A == B)
		{
			// and %rCd, %rAd
			EMIT(0x45); EMIT(0x21); EMIT(0xC0 | C << 3 | A);
			// not %rAd
			EMIT(0x41); EMIT(0xF7); EMIT(0xD0 | A);
		}
		else if(A == C)
		{
			// and %rBd, %rAd
			EMIT(0x45); EMIT(0x21); EMIT(0xC0 | B << 3 | A);
			// not %rAd
			EMIT(0x41); EMIT(0xF7); EMIT(0xD0 | A);
		}
		else if(B == C)
		{
			// mov %rBd, %rAd
			EMIT(0x45); EMIT(0x89); EMIT(0xC0 | B << 3 | A);
			// not %rAd
			EMIT(0x41); EMIT(0xF7); EMIT(0xD0 | A);
		}
		else
		{
			// mov %rBd, %rAd
			EMIT(0x45); EMIT(0x89); EMIT(0xC0 | B << 3 | A);
			// and %rCd, %rAd
			EMIT(0x45); EMIT(0x21); EMIT(0xC0 | C << 3 | A);
			// not %rAd
			EMIT(0x41); EMIT(0xF7); EMIT(0xD0 | A);
		}
		break;
	case 7:
		// ret
		EMIT(0xC3);
		break;
	case 8:
		// mov %rC, %rdi
		EMIT(0x4C); EMIT(0x89); EMIT(0xC7 | C << 3);
		// callq aux_alloc
		EMIT(0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_alloc, 0}; EMIT32(0);
		// mov %eax, %rBd
		EMIT(0x41); EMIT(0x89); EMIT(0xC0 | B);
		break;
	case 9:
		// mov %rC, %rdi
		EMIT(0x4C); EMIT(0x89); EMIT(0xC7 | C << 3);
		// callq aux_abandon
		EMIT(0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_abandon, 0}; EMIT32(0);
		break;
	case 10:
		// mov %rC, %rdi
		EMIT(0x4C); EMIT(0x89); EMIT(0xC7 | C << 3);
		// callq aux_putchar
		EMIT(0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_putchar, 0}; EMIT32(0);
		break;
	case 11:
		// callq aux_getchar
		EMIT(0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_getchar, 0}; EMIT32(0);
		// mov %eax, %rCd
		EMIT(0x49); EMIT(0x89); EMIT(0xC0 | C);
		break;
	case 12:
		// test %rBd, %rBd
		EMIT(0x45); EMIT(0x85); EMIT(0xC0 | B << 3 | B);
		// jz . + 13
		EMIT(0x74); EMIT(0x0B);
		// mov %rB, %rdi
		EMIT(0x4C); EMIT(0x89); EMIT(0xC7 | B << 3);
		// mov %rC, %rsi
		EMIT(0x4C); EMIT(0x89); EMIT(0xC6 | C << 3);
		// call aux_jump;
		EMIT(0xE8); relocs[(*num_relocs)++] = (struct reloc){*p, aux_jump, 0}; EMIT32(0);
		// mov offsets(, %rC, 4), %eax
		EMIT(0x42); EMIT(0x8B); EMIT(0x04); EMIT(0xC5 | C << 3); relocs[(*num_relocs)++] = (struct reloc){*p, ADDR_OFFSETS, 1}; EMIT32(0);
		// jmp *%rax
		EMIT(0xFF); EMIT(0xE0);
		break;
	case 13:
		// mov $IMM, %rAd
		EMIT(0x41); EMIT(0xB8 | immR); EMIT32(immV);
		break;
	default:
		EMIT(0x0F); EMIT(0x0F);
		break;
	}
	// emit(p, d, 4, 0x0F1F0425); emit_imm(p, d, 4, &insn);
#undef EMIT
#undef EMIT32
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

	".global aux_rejit\n"
	"aux_rejit:\n"
	"mov (%rsp), %rdi\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"call aux_c_rejit\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"mov %rax, (%rsp)\n"
	"ret\n"

	".global aux_putchar\n"
	"aux_putchar:\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"call putchar\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"ret\n"

	".global aux_getchar\n"
	"aux_getchar:\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"call getchar\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"ret\n"

	".global aux_dump\n"
	"aux_dump:\n"
	"mov (%rsp), %rsi\n"
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

void aux_c_dump(uint64_t *regs, void *ptr)
{
	size_t i;
	platter_t pc = 0;
	for(i = 0; offsets[i] < (void *)exec_page + exec_page_size; i++)
		if(offsets[i] > ptr)
		{
			pc = i - 1;
			break;
		}
	printf("pc: %08x | %08x |", pc, source[pc]);
	for(i = 0; i < 8; i++)
	{
		printf(" r%ld: %08lx", i, regs[i]);
	}
	printf("\n");
}

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

void **stacks = NULL;
size_t num_stacks = 0;

void *head = NULL;

#define STACK_SZ 8
#define STACK_NUM 65536

void *aux_c_alloc(size_t size)
{
	if(size <= STACK_SZ)
	{
		if(!head)
		{
			stacks = realloc(stacks, sizeof(void *) * (num_stacks + 1));
			platter_t (*stack)[STACK_SZ] = calloc(STACK_NUM, STACK_SZ * sizeof(platter_t));
			stacks[num_stacks++] = stack;
			size_t i;
			for(i = 0; i < STACK_NUM - 1; i++)
				*(void **)&stack[i] = &stack[i + 1];
			head = &stack[0];
		}
		void *addr = head;
		head = *(void **)head;
		memset(addr, 0, size * sizeof(platter_t));
		return addr;
	}
	void *addr = calloc(size * sizeof(platter_t) + sizeof(size_t), 1);
	*(size_t *)addr = size;
	return addr + sizeof(size_t);
}

void aux_c_abandon(void *ptr)
{
	size_t i;
	for(i = 0; i < num_stacks; i++)
		if(ptr >= stacks[i] && ptr < stacks[i] + STACK_SZ * STACK_NUM * sizeof(platter_t))
		{
			*(void **)ptr = head;
			head = ptr;
			return;
		}
	size_t *addr = (size_t *)ptr - 1;
	free(addr);
}

void aux_c_poke(size_t offset, platter_t value)
{
	source[offset] = value;
	*(uint16_t *)offsets[offset] = 0xD3FF;
}

void jit_array(platter_t *array, size_t size)
{
	exec_page_act = PAGE_SIZE;
	exec_page = exec_allocate(exec_page_act);

	offsets = malloc((size + 1) * sizeof(void *));

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

		offsets[i] = exec_page + offset;

		emit_insn(&offset, exec_page, array[i], relocs, &num_relocs);
	}
	offsets[size] = exec_page + offset;
	exec_page_size = offset;

	for(i = 0; i < num_relocs; i++)
		satisfy_reloc(&relocs[i]);

}

void *load_array(void *array, size_t size, size_t offset)
{
	free(relocs);
	act_relocs = num_relocs = 0;
	relocs = NULL;
	exec_free(exec_page, exec_page_act);
	exec_page = NULL;
	exec_page_act = exec_page_size = 0;
	free(offsets);
	offsets = NULL;
	jit_array(array, size);
	return offsets[offset];
}

void *aux_c_jump(void *array, size_t offset)
{
	size_t size, i;
	for(i = 0; i < num_stacks; i++)
		if(array >= stacks[i] && array < stacks[i] + STACK_SZ * STACK_NUM * sizeof(platter_t))
		{
			size = STACK_SZ;
			break;
		}
	if(i >= num_stacks)
		size = ((size_t *)array)[-1];

	free(source);
	source_size = size;
	source = malloc(size * sizeof(platter_t));
	memcpy(source, array, size * sizeof(platter_t));

	return load_array(array, size, offset);
}

void *aux_c_rejit(void *ptr)
{
	platter_t left = 0, right = source_size;
	while(left < right - 1)
	{
		platter_t mid = (left + right) / 2;
		if(offsets[mid] < ptr)
			left = mid;
		else
			right = mid;
	}
	return load_array(source, source_size, left);
}

int main(int argc, char **argv)
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	if(argc < 2)
		exit(EXIT_SUCCESS);
	FILE *f = fopen(argv[1], "rb");
	fseek(f, 0, SEEK_END);
	source_size = ftell(f) / sizeof(platter_t);
	fseek(f, 0, SEEK_SET);
	source = calloc(source_size, sizeof(platter_t));
	size_t i = 0;
	while(i < source_size)
		i += fread(source + i, sizeof(platter_t), source_size - i, f);
	for(i = 0; i < source_size; i++)
	{
		platter_t x = source[i];
		source[i] = ((x & 0xFF000000) >> 24) | ((x & 0xFF0000) >> 8) | ((x & 0xFF00) << 8) | ((x & 0xFF) << 24);
	}

	mallopt(M_MMAP_MAX, 0);

	jit_array(source, source_size);

	asm volatile (
		"xor %%r8, %%r8\n"
		"xor %%r9, %%r9\n"
		"xor %%r10, %%r10\n"
		"xor %%r11, %%r11\n"
		"xor %%r12, %%r12\n"
		"xor %%r13, %%r13\n"
		"xor %%r14, %%r14\n"
		"xor %%r15, %%r15\n"
		"mov $aux_rejit, %%rbx\n"
		"enter_bytecode:\n"
		"call *%0\n"
		:: "o"(exec_page) : "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "%rbx"
	);


	free(relocs);
	exec_free(exec_page, exec_page_act);
	free(source);
	free(offsets);
	for(i = 0; i < num_stacks; i++)
		free(stacks[i]);
}
