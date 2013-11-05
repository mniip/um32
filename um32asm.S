.text
.globl main
.type main, @function

main:
	// grab argv[1]
	popl %eax
	popl %eax
	popl %eax
	movl 4(%eax), %eax
	cmpl $0, %eax
	je bye

	// open file
	push $0 // O_RDONLY
	push %eax
	call open
	addl $8, %esp
	movl %eax, %esi

	// grab size
	pushl $2 // SEEK_END
	pushl $0
	pushl %esi
	call lseek
	addl $12, %esp
	mov %eax, %edi
	pushl $0 // SEEK_SET
	pushl $0
	pushl %esi
	call lseek
	addl $12, %esp

	// allocate array 0
	addl $4, %edi
	push %edi
	call malloc
	addl $4, %esp
	movl %eax, %edx
	movl $0, %ecx

	// read
	push %ebp
	movl %esp, %ebp
	subl $4, %esp // 4-char buffer
readloop:
	pushl %edx
	pushl %ecx
	pushl $4
	pushl %ebp
	pushl %esi
	call read
	addl $12, %esp
	movl (%ebp), %eax
	movl %eax, %ebx // switch endiannes
	andl $0xFFFF0000, %eax
	andl $0xFFFF, %ebx
	shr $16, %eax
	shl $16, %ebx
	orl %ebx, %eax
	movl %eax, %ebx
	andl $0xFF00FF00, %eax
	andl $0xFF00FF, %ebx
	shr $8, %eax
	shl $8, %ebx
	orl %ebx, %eax
	popl %ecx
	popl %edx
	movl %eax, (%edx, %ecx)
	addl $4, %ecx
	cmpl %edi, %ecx
	jl readloop

	movl %ebp, %esp
	subl $32, %esp // 8 4-byte registers
	movl $0, 0(%ebp)
	movl $0, 4(%ebp)
	movl $0, 8(%ebp)
	movl $0, 12(%ebp)
	movl $0, 16(%ebp)
	movl $0, 20(%ebp)
	movl $0, 24(%ebp)
	movl $0, 28(%ebp)
	movl %edx, %esi
	movl $0, %edi

	// let the thing begin
mainloop:
	movl (%esi, %edi, 4), %edx
	incl %edi
	cmpl $0xd0000000, %edx
	jnae not_o13
	movl %edx, %eax
	shr $25, %eax
	and $7, %eax // A register
	and $0x1ffffff, %edx // value
	movl %edx, (%ebp, %eax, 4)
	jmp mainloop
not_o13:
	movl %edx, %eax
	shr $6, %eax
	andl $7, %eax // A register
	movl %edx, %ebx
	shr $3, %ebx
	andl $7, %ebx // B register
	movl %edx, %ecx
	andl $7, %ecx // C register
	shr $28, %edx // opcode
	cmpl $0, %edx
	je o0
	cmpl $1, %edx
	je o1
	cmpl $2, %edx
	je o2
	cmpl $3, %edx
	je o3
	cmpl $4, %edx
	je o4
	cmpl $5, %edx
	je o5
	cmpl $6, %edx
	je o6
	cmpl $7, %edx
	je o7
	cmpl $8, %edx
	je o8
	cmpl $9, %edx
	je o9
	cmpl $10, %edx
	je o10
	cmpl $11, %edx
	je o11
	jmp o12
o0:
	// 0: conditional move
	cmpl $0, (%ebp, %ecx, 4)
	je mainloop
	movl (%ebp, %ebx, 4), %edx
	movl %edx, (%ebp, %eax, 4)
	jmp mainloop

o1:
	// 1: array peek
	movl (%ebp, %ebx, 4), %ebx
	cmpl $0, %ebx
	je peekcode
	movl (%ebp, %ecx, 4), %ecx
	incl %ecx
	movl (%ebx, %ecx, 4), %ebx
	movl %ebx, (%ebp, %eax, 4)
	jmp mainloop
peekcode:
	movl (%ebp, %ecx, 4), %ecx
	movl (%esi, %ecx, 4), %ecx
	movl %ecx, (%ebp, %eax, 4)
	jmp mainloop

o2:
	// 2: array poke
	movl (%ebp, %eax, 4), %eax
	cmpl $0, %eax
	je pokecode
	movl (%ebp, %ebx, 4), %ebx
	incl %ebx
	movl (%ebp, %ecx, 4), %ecx
	movl %ecx, (%eax, %ebx, 4)
	jmp mainloop
pokecode:
	movl (%ebp, %ebx, 4), %ebx
	movl (%ebp, %ecx, 4), %ecx
	movl %ecx, (%esi, %ebx, 4)
	jmp mainloop

o3:
	// 3: add
	movl (%ebp, %ebx, 4), %edx
	addl (%ebp, %ecx, 4), %edx
	movl %edx, (%ebp, %eax, 4)
	jmp mainloop

o4:
	// 4: multiply
	pushl %eax
	movl (%ebp, %ebx, 4), %eax
	mull (%ebp, %ecx, 4)
	popl %ebx
	movl %eax, (%ebp, %ebx, 4)
	jmp mainloop

o5:
	// 5: divide
	movl $0, %edx
	pushl %eax
	movl (%ebp, %ebx, 4), %eax
	divl (%ebp, %ecx, 4)
	popl %ebx
	movl %eax, (%ebp, %ebx, 4)
	jmp mainloop

o6:
	// 6: nand
	movl (%ebp, %ebx, 4), %edx
	andl (%ebp, %ecx, 4), %edx
	notl %edx
	movl %edx, (%ebp, %eax, 4)
	jmp mainloop

o7:
	// 7: halt
	jmp bye

o8:
	// 8: allocation
	pushl %ebx
	mov (%ebp, %ecx, 4), %ecx
	inc %ecx
	pushl $4
	pushl %ecx
	call calloc
	popl %ecx
	movl %ecx, (%eax)
	popl %edx
	popl %ebx
	movl %eax, (%ebp, %ebx, 4)
	jmp mainloop

o9:
	// 9: abandonment
	pushl (%ebp, %ecx, 4)
	call free
	addl $4, %esp
	jmp mainloop

o10:
	// 10: output
	lea (%ebp, %ecx, 4), %ecx
	pushl $1
	pushl %ecx
	pushl $1
	call write
	addl $12, %esp
	jmp mainloop

o11:
	// 11: input
	pushl %ecx
	call getchar
	popl %ecx
	movl %ecx, (%ebp, %ecx, 4)
	jmp mainloop

o12:
	// 12: jump
	cmpl $0, (%ebp, %ebx, 4)
	je modfinger
a:
	movl (%ebp, %ebx, 4), %ebx
	pushl %ecx
	pushl %ebx
	pushl %esi
	call free
	addl $4, %esp
	popl %ebx
	movl (%ebx), %edx
	shl $2, %edx
	pushl %ebx
	pushl %edx
	call malloc
	popl %edx
	popl %ebx
	movl %eax, %esi
	addl $4, %ebx
	pushl %edx
	pushl %ebx
	pushl %esi
	call memcpy
	addl $12, %esp
	popl %ecx
modfinger:
	mov (%ebp, %ecx, 4), %edi
	jmp mainloop

bye:
	push $1
	call fsync
	movl $1, %eax
	movl $0, %ebx
	int $0x80
	.size main, . - main
