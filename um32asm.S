.text
.globl main
.type main, @function

main:
	// grab argv[1]
	popl %eax
	popl %eax
	popl %eax
	movl 4(%eax), %eax
	cmp $0, %eax
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
	cmp %edi, %ecx
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
/*
	pushl 28(%ebp)
	pushl 24(%ebp)
	pushl 20(%ebp)
	pushl 16(%ebp)
	pushl 12(%ebp)
	pushl 8(%ebp)
	pushl 4(%ebp)
	pushl (%ebp)
	push $str2
	call printf
	addl $36, %esp
*/
	movl (%esi, %edi, 4), %edx
	inc %edi
	cmp $0xd0000000, %edx
	jnae not_13
	movl %edx, %eax
	shr $25, %eax
	and $7, %eax // A register
	and $0x1ffffff, %edx // value
	movl %edx, (%ebp, %eax, 4)
	jmp mainloop
not_13:
	movl %edx, %eax
	shr $6, %eax
	andl $7, %eax // A register
	movl %edx, %ebx
	shr $3, %ebx
	andl $7, %ebx // B register
	movl %edx, %ecx
	shr $28, %ecx // opcode
	andl $7, %edx // C register
	cmp $0, %ecx
	jne not_0
	// 0: conditional move
	cmp $0, (%ebp, %edx, 4)
	je mainloop
	movl (%ebp, %ebx, 4), %ecx
	movl %ecx, (%ebp, %eax, 4)
	jmp mainloop

not_0:
	loop not_1
asd:
	// 1: array peek
	movl (%ebp, %ebx, 4), %ebx
	cmp $0, %ebx
	je peekcode
	movl (%ebp, %edx, 4), %edx
	incl %edx
	movl (%ebx, %edx, 4), %ebx
	movl %ebx, (%ebp, %eax, 4)
	jmp mainloop
peekcode:
	movl (%ebp, %edx, 4), %edx
	movl (%esi, %edx, 4), %edx
	movl %edx, (%ebp, %eax, 4)
	jmp mainloop

not_1:
	loop not_2
	// 2: array poke
	movl (%ebp, %eax, 4), %eax
	cmp $0, %eax
	je pokecode
	movl (%ebp, %ebx, 4), %ebx
	incl %ebx
	movl (%ebp, %edx, 4), %edx
	movl %edx, (%eax, %ebx, 4)
	jmp mainloop
pokecode:
	movl (%ebp, %ebx, 4), %ebx
	movl (%ebp, %edx, 4), %edx
	movl %edx, (%esi, %ebx, 4)
	jmp mainloop

not_2:
	loop not_3
	// 3: add
	movl (%ebp, %ebx, 4), %ecx
	addl (%ebp, %edx, 4), %ecx
	movl %ecx, (%ebp, %eax, 4)
	jmp mainloop

not_3:
	loop not_4
	// 4: multiply
	pushl %eax
	movl (%ebp, %ebx, 4), %eax
	mull (%ebp, %edx, 4)
	popl %ebx
	movl %eax, (%ebp, %ebx, 4)
	jmp mainloop

not_4:
	loop not_5
	// 5: divide
	movl %edx, %ecx
	movl $0, %edx
	pushl %eax
	movl (%ebp, %ebx, 4), %eax
	divl (%ebp, %ecx, 4)
	popl %ebx
	movl %eax, (%ebp, %ebx, 4)
	jmp mainloop

not_5:
	loop not_6
	// 6: nand
	movl (%ebp, %ebx, 4), %ecx
	andl (%ebp, %edx, 4), %ecx
	notl %ecx
	movl %ecx, (%ebp, %eax, 4)
	jmp mainloop

not_6:
	loop not_7
	// 7: halt
	jmp bye

not_7:
	loop not_8
	// 8: allocation
	pushl %ebx
	mov (%ebp, %edx, 4), %edx
	inc %edx
	pushl $4
	pushl %edx
	call calloc
	popl %edx
	movl %edx, (%eax)
	popl %ecx
	popl %ebx
	movl %eax, (%ebp, %ebx, 4)
	jmp mainloop

not_8:
	loop not_9
	// 9: abandonment
	pushl (%ebp, %edx, 4)
	call free
	addl $4, %esp
	jmp mainloop

not_9:
	loop not_10
	// 10: output
	pushl (%ebp, %edx, 4)
	call putchar
	addl $4, %esp
	jmp mainloop

not_10:
	loop not_11
	// 11: input
	pushl %edx
	call getchar
	popl %edx
	movl %edx, (%ebp, %edx, 4)
	jmp mainloop

not_11:
	// 12: jump
	cmp $0, (%ebp, %ebx, 4)
	je modfinger
a:
	movl (%ebp, %ebx, 4), %ebx
	pushl %edx
	pushl %ebx
	movl (%ebx), %ecx
	decl %ecx
	shl $2, %ecx
	pushl %ecx
	pushl %esi
	call realloc
	movl %eax, %esi
	popl %ecx
	popl %ecx
	popl %ebx
	addl $4, %ebx
	pushl %ecx
	pushl %ebx
	pushl %esi
	call memcpy
	addl $12, %esp
	popl %edx
modfinger:
	mov (%ebp, %edx, 4), %edi
	jmp mainloop

bye:
	push $1
	call fsync
	movl $1, %eax
	movl $0, %ebx
	int $0x80
	.size main, . - main
