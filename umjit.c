#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include <sys/mman.h>

void *mmalloc(size_t length)
{
	void *addr = mmap(NULL, length, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(addr == (void*)-1)
	{
		perror("mmap");
		exit(EXIT_FAILURE);
	}
	return addr;
}

void mfree(void *addr, size_t length)
{
	if(-1 == munmap(addr, length))
	{
		perror("munmap");
		exit(EXIT_FAILURE);
	}
}

typedef uint32_t platter_t;
static platter_t *source;
static void *code;
static int size;

void emit(void *page, size_t base, platter_t opcode);
void emit_page(void *page, int size, platter_t *source);

#define OPCODE_SIZE 37
#define EXPAND(X) #X
#define MTOS(X) EXPAND(X)

void inl_poke(platter_t value, int offset);
asm
(
 	".globl inl_poke\n"
 	".type inl_poke, @function\n"
 	"inl_poke:\n"
	"pushq %r8\n"
	"pushq %r9\n"
	"pushq %r10\n"
	"pushq %r11\n"
	"movq source, %rbx\n"
	"movl %edi, (%ebx, %esi, 4)\n"
	"movq %rdi, %rdx\n"
	"movq code, %rdi\n"
	"imulq $" MTOS(OPCODE_SIZE) ", %rsi\n"
 	"call emit\n"
	"popq %r11\n"
	"popq %r10\n"
	"popq %r9\n"
	"popq %r8\n"
	"addq $" MTOS(OPCODE_SIZE - 29) ", (%rsp)\n"
	"retq\n"
 	".size inl_poke, .-inl_poke\n"
);

int inl_alloc(int size);
asm
(
 	".globl inl_alloc\n"
 	".type inl_alloc, @function\n"
 	"inl_alloc:\n" 
	"pushq %r8\n"
	"pushq %r9\n"
	"pushq %r10\n"
	"pushq %r11\n"
	"pushq %rdi\n"
 	"incl %edi\n"
	"movl $4, %esi\n"
 	"call calloc\n"
	"popq %rdi\n"
	"movl %edi, (%eax)\n"
 	"addl $4, %eax\n"
	"popq %r11\n"
	"popq %r10\n"
	"popq %r9\n"
	"popq %r8\n"
	"retq\n"
 	".size inl_alloc, .-inl_alloc\n"
);

void inl_jump(void *arr, int offset);
asm
(
 	".globl inl_jump\n"
 	".type inl_jump, @function\n"
 	"inl_jump:\n" 
	"push %rbp\n"
	"mov %rsp,%rbp\n"
	"sub $0x20,%rsp\n"
	"push %rsi\n"
	"mov %rdi,-0x18(%rbp)\n"
	"mov %esi,-0x1c(%rbp)\n"
	"push %r8\n"
	"push %r9\n"
	"push %r10\n"
	"push %r11\n"
	"mov size,%eax \n"
	"mov %eax,-0x4(%rbp)\n"
	"mov -0x18(%rbp),%rax\n"
	"sub $0x4,%rax\n"
	"mov (%rax),%eax\n"
	"mov %eax,size\n"
	"mov source,%rdi\n"
	"callq free\n"
	"mov size,%eax \n"
	"cltq\n"
	"mov $0x4,%esi\n"
	"mov %rax,%rdi\n"
	"callq calloc\n"
	"mov %rax,source\n"
	"mov size,%eax\n"
	"cltq \n"
	"lea 0x0(,%rax,4),%rdx\n"
	"mov source,%rax\n"
	"mov -0x18(%rbp),%rcx\n"
	"mov %rcx,%rsi\n"
	"mov %rax,%rdi\n"
	"callq memcpy@plt\n"
	"mov -0x4(%rbp),%eax\n"
	"imull $" MTOS(OPCODE_SIZE) ",%eax\n"
	"movslq %eax,%rdx\n"
	"mov code,%rax\n"
	"mov %rdx,%rsi\n"
	"mov %rax,%rdi\n"
	"callq mfree\n"
	"mov size,%eax \n"
	"imull $" MTOS(OPCODE_SIZE) ",%eax\n"
	"cltq\n"
	"mov %rax,%rdi\n"
	"callq mmalloc\n"
	"mov %rax,code\n"
	"mov source,%rdx\n"
	"mov size,%ecx\n"
	"mov code,%rax\n"
	"mov %ecx,%esi\n"
	"mov %rax,%rdi\n"
	"callq emit_page\n"
	"pop %r11\n"
	"pop %r10\n"
	"pop %r9\n"
	"pop %r8\n"
	"pop %rax\n"
	"imul $" MTOS(OPCODE_SIZE) ",%rax,%rax\n"
	"add code,%rax\n"
	"mov %rax,0x8(%rbp)\n"
	"leaveq\n"
	"retq\n"
 	".size inl_jump, .-inl_jump\n"
);

typedef enum
{
	CONDMOVE, PEEK, POKE, ADD, MULTIPLY, DIVIDE, NAND, HALT, ALLOCATE, ABANDON, OUTPUT, INPUT, JUMP, IMMEDIATE
}
mnemonic_t;

void emit(void *page, size_t base, platter_t opcode)
{
	size_t offset = base;
	mnemonic_t mnemonic = opcode >> 28;
#define GET_A ((opcode >> 6) & 7)
#define GET_B ((opcode >> 3) & 7)
#define GET_C (opcode & 7)
#define GET_IMMR ((opcode >> 25) & 7)
#define GET_IMMV (opcode & 0x1FFFFFF)

#define E(byte) ((char *)page)[offset++] = (byte)

#define E_NEXT ((char *)page)[offset] = OPCODE_SIZE - (offset - base) - 1; offset++

#define REG_L(base, reg) ((base) | (reg))
#define REG_H(base, reg) ((base) | ((reg) << 3))
#define REG_HL(base, regH, regL) ((base) | ((regH) << 3) | (regL))
#define E_IMM32(value) *((uint32_t *)(((char *)page) + offset)) = value; offset += 4

	switch(mnemonic)
	{
		case CONDMOVE:
			// cmpl $0, %rCd
			E(0x41); E(0x83); E(REG_L(0xF8, GET_C)); E(0x00);
			// je next
			E(0x74); E_NEXT;
			// movl %rBd, %rAd
			E(0x45); E(0x89); E(REG_HL(0xC0, GET_B, GET_A));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case PEEK:
			// cmpl $0, %rBd
			E(0x41); E(0x83); E(REG_L(0xF8, GET_B)); E(0x00);
			// je . + 8
			E(0x74); E(0x07);
			// movl (%rBd, %rCd, 4), %rAd
			if(GET_B != 5) // XXX: WTF intel
			{
				E(0x67); E(0x47); E(0x8B); E(REG_H(0x04, GET_A)); E(REG_HL(0x80, GET_C, GET_B));
			}
			else
			{
				E(0x67); E(0x47); E(0x8B); E(REG_H(0x44, GET_A)); E(REG_H(0x85, GET_C)); E(0x00);
			}
			// jmp next
			E(0xEB); E_NEXT;
			// movl source, %edx
			E(0x8B); E(0x14); E(0x25); E_IMM32((uintptr_t)&source);
			// movl (%edx, %rCd, 4), %rAd
			E(0x67); E(0x46); E(0x8B); E(REG_H(0x04, GET_A)); E(REG_H(0x82, GET_C));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case POKE:
			// cmpl $0, %rAd
			E(0x41); E(0x83); E(REG_L(0xF8, GET_A)); E(0x00);
			// je . + 8
			E(0x74); E(0x08);
			if(GET_A != 5) // XXX: WTF intel?
			{
				// movl %rCd, (%rAd, %rBd, 4)
				E(0x67); E(0x47); E(0x89); E(REG_H(0x04, GET_C)); E(REG_HL(0x80, GET_B, GET_A));
				// nop
				E(0x90);
			}
			else
			{
				// movl %rCd, 0(%r13d, %rBd, 4)
				E(0x67); E(0x47); E(0x89); E(REG_H(0x44, GET_C)); E(REG_H(0x85, GET_B)); E(0x00);
			}
			// jmp next
			E(0xEB); E_NEXT;
			// movq %rC, %rdi
			E(0x4C); E(0x89); E(REG_H(0xC7, GET_C));
			// movq %rBd, %esi
			E(0x44); E(0x89); E(REG_H(0xC6, GET_B));
			// movq $inl_poke, %rax
			E(0x48); E(0xC7); E(0xC0); E_IMM32((uintptr_t)inl_poke);
			// callq *%rax
			E(0xFF); E(0xD0);
			break;
		case ADD:
			// movl %rBd, %eax
			E(0x44); E(0x89); E(REG_H(0xC0, GET_B));
			// addl %rCd, %eax
			E(0x44); E(0x01); E(REG_H(0xC0, GET_C));
			// movl %eax, %rAd
			E(0x41); E(0x89); E(REG_L(0xC0, GET_A));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case MULTIPLY:
			// movl %rBd, %eax
			E(0x44); E(0x89); E(REG_H(0xC0, GET_B));
			// mull %rCd
			E(0x41); E(0xF7); E(REG_L(0xE0, GET_C));
			// movl %eax, %rAd
			E(0x41); E(0x89); E(REG_L(0xC0, GET_A));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case DIVIDE:
			// movl %rBd, %eax
			E(0x44); E(0x89); E(REG_H(0xC0, GET_B));
			// xorl %edx, %edx
			E(0x31); E(0xD2);
			// divl %rCd
			E(0x41); E(0xF7); E(REG_L(0xF0, GET_C));
			// movl %eax, %rAd
			E(0x41); E(0x89); E(REG_L(0xC0, GET_A));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case NAND:
			// movl %rBd, %eax
			E(0x44); E(0x89); E(REG_H(0xC0, GET_B));
			// andl %rCd, %eax
			E(0x44); E(0x21); E(REG_H(0xC0, GET_C));
			// notl %eax
			E(0xF7); E(0xD0);
			// movl %eax, %rAd
			E(0x41); E(0x89); E(REG_L(0xC0, GET_A));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case HALT:
			// xorq %rdi, %rdi
			E(0x48); E(0x31); E(0xFF);
			// movq $exit, %rax
			E(0x48); E(0xC7); E(0xC0); E_IMM32((uintptr_t)exit);
			// callq *%rax
			E(0xFF); E(0xD0);
			break;
		case ALLOCATE:
			// movq %rC, %rdi
			E(0x4C); E(0x89); E(REG_H(0xC7, GET_C));
			// movq $inl_alloc, %rax
			E(0x48); E(0xC7); E(0xC0); E_IMM32((uintptr_t)inl_alloc);
			// callq *%rax
			E(0xFF); E(0xD0);
			// movl %eax, %rBd
			E(0x41); E(0x89); E(REG_L(0xC0, GET_B));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case ABANDON:
			// movq %rC, %rdi
			E(0x4C); E(0x89); E(REG_H(0xC7, GET_C));
			// subq $4, %rdi
			E(0x48); E(0x83); E(0xEF); E(0x04);
			// pushq %r8
			E(0x41); E(0x50);
			// pushq %r9
			E(0x41); E(0x51);
			// pushq %r10
			E(0x41); E(0x52);
			// pushq %r11
			E(0x41); E(0x53);
			// movq $free, %rax
			E(0x48); E(0xC7); E(0xC0); E_IMM32((uintptr_t)free);
			// callq *%rax
			E(0xFF); E(0xD0);
			// popq %r11
			E(0x41); E(0x5B);
			// popq %r10
			E(0x41); E(0x5A);
			// popq %r9
			E(0x41); E(0x59);
			// popq %r8
			E(0x41); E(0x58);
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case OUTPUT:
			// movq %rC, %rdi
			E(0x4C); E(0x89); E(REG_H(0xC7, GET_C));
			// movq $putchar, %rax
			E(0x48); E(0xC7); E(0xC0); E_IMM32((uintptr_t)putchar);
			// pushq %r8
			E(0x41); E(0x50);
			// pushq %r9
			E(0x41); E(0x51);
			// pushq %r10
			E(0x41); E(0x52);
			// pushq %r11
			E(0x41); E(0x53);
			// callq *%rax
			E(0xFF); E(0xD0);
			// popq %r11
			E(0x41); E(0x5B);
			// popq %r10
			E(0x41); E(0x5A);
			// popq %r9
			E(0x41); E(0x59);
			// popq %r8
			E(0x41); E(0x58);
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case INPUT:
			// movq $getchar, %rax
			E(0x48); E(0xC7); E(0xC0); E_IMM32((uintptr_t)getchar);
			// pushq %r8
			E(0x41); E(0x50);
			// pushq %r9
			E(0x41); E(0x51);
			// pushq %r10
			E(0x41); E(0x52);
			// pushq %r11
			E(0x41); E(0x53);
			// callq *%rax
			E(0xFF); E(0xD0);
			// popq %r11
			E(0x41); E(0x5B);
			// popq %r10
			E(0x41); E(0x5A);
			// popq %r9
			E(0x41); E(0x59);
			// popq %r8
			E(0x41); E(0x58);
			// movl %eax, %rCd
			E(0x41); E(0x89); E(REG_L(0xC0, GET_C));
			// jmp next
			E(0xEB); E_NEXT;
			break;
		case JUMP:
			// cmpl $0, %rBd
			E(0x41); E(0x83); E(REG_L(0xF8, GET_B)); E(0x00);
			// je . + 15
			E(0x74); E(0x0F);
			// movq %rB, %rdi
			E(0x4C); E(0x89); E(REG_H(0xC7, GET_B));
			// movl %rCd, %esi
			E(0x44); E(0x89); E(REG_H(0xC6, GET_C));
			// movq $inl_jump, %rax
			E(0x48); E(0xC7); E(0xC0); E_IMM32((uintptr_t)inl_jump);
			// callq *%rax
			E(0xFF); E(0xD0);
			// imul %rC, $OPCODE_SIZE, %rax
			E(0x49); E(0x6B); E(REG_L(0xC0, GET_C)); E(OPCODE_SIZE);
			// leaq -offset(%rip), %rbx
			E(0x48); E(0x8D); E(0x1D); E_IMM32(~(uintptr_t)offset-3);
			// addq %rbx, %rax
			E(0x48); E(0x01); E(0xD8);
			// jmpq %rax
			E(0xFF); E(0xE0);
			break;
		case IMMEDIATE:
			// movl %rAd, $IMM
			E(0x41); E(REG_L(0xB8, GET_IMMR)); E_IMM32(GET_IMMV);
			// jmp next
			E(0xEB); E_NEXT;
			break;
		default:
			E(0x89); E(0x04); E(0x25); E_IMM32(opcode);
			E(0xEB); E_NEXT;
			break;
	}
}

void emit_page(void *page, int size, platter_t *source)
{
	int i;
	for(i = 0; i < size; i++)
	{
		emit(page, i * OPCODE_SIZE, source[i]);
	}
}

int main(int argc, char *argv[])
{
	if(argc<2)
		exit(EXIT_SUCCESS);
	mallopt(M_MMAP_MAX, 0);
	FILE *f = fopen(argv[1], "rb");
	fseek(f, 0, SEEK_END);
	size = ftell(f) / sizeof(platter_t);
	fseek(f, 0, SEEK_SET);
	source = calloc(size, sizeof(platter_t));
	int i = 0;
	while(i < size)
		i += fread(source + i, sizeof(platter_t), size - i, f);
	for(i = 0; i < size; i++)
	{
		platter_t x = source[i];
		source[i] = ((x & 0xFF000000) >> 24) | ((x & 0xFF0000) >> 8) | ((x & 0xFF00) << 8) | ((x & 0xFF) << 24);
	}
	code = mmalloc(size * OPCODE_SIZE);
	emit_page(code, size, source);
	asm
	(
		"xorl %r8d, %r8d\n"
		"movl %r8d, %r9d\n"
		"movl %r8d, %r10d\n"
		"movl %r8d, %r11d\n"
		"movl %r8d, %r12d\n"
		"movl %r8d, %r13d\n"
		"movl %r8d, %r14d\n"
		"movl %r8d, %r15d\n"
		"movq code(%rip), %rdx\n"
		"r:\n"
		"callq *%rdx\n"
	);
	mfree(code, size * OPCODE_SIZE);
	return 0;
}
