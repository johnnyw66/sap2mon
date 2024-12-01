	.org 0
	clc
	movwi r0,0x0000
	movwi r2,0x0100
	call hexdump


	movwi r0, 0x1234
	movwi r2, 0x5678
	call regdump
	exx
	movwi r0, 0xabcd
	movwi r2, 0xef00
	call regdump
	exx
	#call buildflags_str


	hlt


:regdump
	push r0
	push r2

	# R0
	push r0
	movwi r0,r0_
	call printreg
	pop r0
	
	mov r0, r0
	call printhex
	call printspace

	# R1
	push r0
	movwi r0,r1_
	call printreg
	pop r0

	mov r0, r1
	call printhex
	call printspace

	# R2
	push r0
	movwi r0,r2_
	call printreg
	pop r0

	mov r0, r2
	call printhex
	call printspace

	# R3
	push r0
	movwi r0,r3_
	call printreg
	pop r0

	mov r0, r3
	call printhex
	call printspace


	# TODO SP, PC, Flags

	# Carriage Return
	call printcr

	pop r2
	pop r0
	ret

:printreg
	call print
	movi r0,0x3a
	out r0
	movi r0,32
	out r0
	movwi r0,hex
	call print
	ret

:hex
	.dt '0x'	
:r0_
	.dt 'R0'
:r1_
	.dt 'R1'
:r2_
	.dt 'R2'
:r3_
	.dt 'R3'

:sp_
	.dt 'SP'

:pc_
	.dt 'PC'


# Test each flag and 
:buildflags_str
	movi r2,0
	movi r3,1
	movwi r0,zero_flag
	st r2, (r0)
	jpz zflg
	st r3, (r0)
:zflg
	movwi r0,carry_flag
	st r2, (r0)
	jpc cflg
	st r3, (r0)
:cflg
	movwi r0,sign_flag
	st r2, (r0)
	jpns sflg
	st r3, (r0)
:sflg
	movwi r0,over_flag
	st r2, (r0)
	jpnv oflg
	st r3, (r0)
:oflg

#	movwi r0,parity_flag
#	st r2, (r0)
#	jpv pflg
#	st r3, (r0)

	ret

	
:hexdump
#   Hex dump - r0r1 is address
#   r2r3 number of bytes

	push r0

	mov r0,r3
	andi r0, 0x1f	# r0 contains final size of dump % 32
				

	#andi r2,0xff # Maximum number of 32*256 bytes

	clc

	shr	r2
	shr	r3

	shr r2
	shr	r3

	shr r2
	shr	r3

	shr r2
	shr	r3

	shr r2
	shr	r3


	andi r3,0xff
	mov r2, r0

	pop r0
	# r3 contains number of 32 sized lines
	# r2 contains remainder number of bytes for final line
	# r0 address where to dump from

	andi r3,0xff
	jpz remainder_dump
	
	push r2
	movi r2, 32
	call dumpline
	pop r2

:remainder_dump
	andi r2, 0xff
	jpz noremainder
	movi r3, 65
	out r3
	movi r3, 1
	call dumpline
:noremainder
	ret
	

:dumpline
#   r2 size of line
#   r3 is number of lines

	push r2
	call dumpmemoryline
	pop r2
	djnz r3, dumpline
	ret


:printcr
	push r0
	movi r0,13
	out r0
	movi r0,10
	out r0
	pop r0
	ret

:printspace
	push r0
	movi r0,0x20
	out r0
	pop r0
	ret

:dumpmemoryline
	# r0r1
	#movi r2,32
	
	call printhexword
	call printspace
	call printspace
	

:dumphexbytes
	ld r3,(r0)

	inc r1
	jpnc cplush
	inc r0
:cplush
	push r0
	push r2
	mov r0,r3
	call printhex
	call printspace
	pop r2
	pop r0
		
	djnz r2,dumphexbytes

	call printspace
	call printspace



	call printcr

	ret

	

:printhexword
	# print r0r1
	push r0
	push r2
	
	call printhex
	mov r0, r1
	call printhex
	
	pop r2
	pop r0
	ret


	
:printhex
	# Print r0 in hex
	push r0
	push r2
	mov r1, r0
	clc
	shr r1
	clc
	shr r1
	clc
	shr r1
	clc
	shr r1
	mov r3,r1
	addi r1,48
	subi r3,10
	jpc nbig9L
	addi r1,7
:nbig9L
	out r1

	andi r0,0x0f
	mov r3,r0
	addi r0,48
	subi r3,10
	jpc nbig9H
	addi r0,7
:nbig9H
	out r0

	pop r2
	pop r0
	ret

:print
	push r0
	push r2

:loop
	ld r2,(r0)
	and r2,r2
	jpz finish
	out r2
	addi r1, 1
	jpnc loop
	addi r0, 1
	jmp loop
:finish
	pop r2
	pop r0
	ret

:welcome
	.dt '***SAP2 MONITOR****'
:complete
	.dt 'You have done it!'

	.org 0xFF00
:zero_flag
	.db 0xf0
:carry_flag
	.db 0xf1
:sign_flag
	.db 0xf2
:over_flag
	.db 0xf3
:parity_flag
	.db 0xf4
	.db 0xff

	.end

