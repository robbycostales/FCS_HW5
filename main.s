.data

EncryptedPhrase: .word 0x5f7fb06, 0xfb06f2f8, 0xc0704fb, 0xf9fbf7f3, 0x6f306fb, 0x700f809, 0xf805f30b, 0xf300f808, 0xf7080706, 0x60700f8, 0x8f3faf3, 0x4f5f2f7, 0xf7fdf5f4, 0x801f2f7, 0x1f5f304, 0xf2f6f7f7, 0x605f7ff, 0xf2f7f9f3, 0xfaf401f7, 0x0				# 20 length

End: .asciiz "That's All!"
Found: .asciiz "Word found: "
NewLine: .asciiz "\n"

DecryptionSpace: .space 400 # 400 bytes of space, more than enough...

# .globl main
# .globl WordDecrypt
# .globl IsCandidate
# .globl AddandVerify

.text

main:
	la $t3, EncryptedPhrase			# put address of list into $t3
	li $t7, 0x01010101					# initialize current key
	li $t6, 0x01010101					# add $t6 to key every iteration
	# iterate through 255 different keys
mainLoop:
	move $a0, $t3								# encrypted phrase --> first parameter
	la $a1, DecryptionSpace			# decrypted space --> second parameter
	move $a2, $t7								# current key --> third parameter

	# save variables to stack
	addi $sp, $sp, -24
	sw $a0, 0($sp)
	sw $a1, 4($sp)
	sw $a2, 8($sp)
	sw $t3, 12($sp)
	sw $t7, 16($sp)
	sw $t6, 20($sp)

	# input: 		($a0: address of EP; $a1: decrypted string placeholder address; $a2: key K (word))
	# output:		($v0: 1 if valid, ow 0; $v1 carry)
	jal AddAndVerify						# check phrase against key

	# save variables to stack
	lw $a0, 0($sp)
	lw $a1, 4($sp)
	lw $a2, 8($sp)
	lw $t3, 12($sp)
	lw $t7, 16($sp)
	lw $t6, 20($sp)
	addi $sp, $sp, 24

	beq $v0, 1, Found						# if valid, we found the right key
addForNext:
	addu $t7, $t7, $t6
	bne $t7, 0xFFFFFFFF, mainLoop
end: 										# if $t7 loops back to 0x00000000, we did not find a solution
	la $a0, End
	li $v0, 4
	syscall											# print not found message
	li $v0, 10
	syscall
found:
	la $a0, Found
	li $v0, 4
	syscall											# print found message

	move $a0, $t7
	li $v0, 4
	syscall											# print key

	la $a0, NewLine
	li $v0, 4
	syscall											# print newline
	# return to main loop
	j addForNext

# input: 		($a0: encrypted word, $a1: key word, $a2: carry val)
# output:		($v0: result of addition, $v1: carry val)
WordDecrypt:
	addu $t0, $a0, $a1
	addu $v0, $t0, $a2			# $v0 = $a0 + $a1 + $a2
	# $v1 stores carry val (if a1>=a0+a1+a2, 1; ow 0)
 	sltu $t0, $a1, $v0			# test $a1 < $v0, result into $t0
	beq $t0, 0, ElseWD			# if false, goto ElseWD
	li $v1, 0								# if true, set to 0
	j EndifWD
ElseWD:
	li $v1, 1
EndifWD:
	jr $ra


# input:		($a0 valid or invalid bytes)
# output:		($v0, 1 if all valid, 0 if not)
IsCandidate:
	li $t8, -1						# $t8 is iterator
nextComp:
	add $t8, $t8, 1				# increment iterator
	beq $t8, 4, trueIC		# if already compared last, return true
	# make mask
	li $t0, 255						# $t0 is the mask
	# check each character
	and $t1, $t0, $a0			# $t1 isolated with mask
	srl $a0, $a0, 8				# shift $a0 right for next comparison
	sltiu $t2, $t1, 91		# check if $t1 is less than 91
	li $t4, 63						# need non-immediate for next condition
	sltu $t3, $t4, $t1		# check if 63 is less than $t1
	addu $t5, $t2, $t3		#	add condition outputs --> $t5
	beq $t5, 2, nextComp	# if $t5==2 (both conditions are true), continue
	# if it makes it here, false
	li $v0, 0
	jr $ra
trueIC:
	li $v0, 1
	jr $ra


	# input: 		($a0: address of EP; $a1: decrypted string placeholder address; $a2: key K (word))
	# output:		($v0: 1 if valid, ow 0; $v1 carry)
	AddAndVerify:
		# save variables to stack
		addi $sp, $sp, -16
		sw $ra, 0($sp)		# save return address
		sw $a0, 4($sp)		# save init EP address
		sw $a1, 8($sp)		# save decrypted address
		sw $a2, 12($sp)		# save key K

		lw $t0, 0($a0)				# $t0 is current word
		# Base case
		beq $t0, 0, endMsg		# if word is 0, end of message
		# Otherwise
		addiu $a0, $a0, 4		# increment decrypted string addr
		addiu $a1, $a1, 4	  # increment decrypted string addr

		# input: 		($a0: address of EP; $a1: decrypted string placeholder address; $a2: key K (word))
		# output:		($v0: 1 if valid, ow 0; $v1 carry)
		jal AddAndVerify
		beq $v0, 0, invalid		# if invalid, return
		# if valid
		lw $t0, -4($a0)
		move $a0, $t0          # want non-zero encrypted word as first input
		move $a1, $a2          # a2 from AddAndVerify = keyword, second input to WD
		move $a2, $v1          # carry value transfer

		# input: 		($a0: encrypted word, $a1: key word, $a2: carry val)
		# output:		($v0: result of addition, $v1: carry val)
		jal WordDecrypt

		lw $a1, 8($sp)          # get correct value for $a1 (because it was overwritten)
		sw $v0, 0($a1)          # save result of addition to $a1
		# sw $a1, 8($sp)

		move $a0, $v0
		# input:		($a0 valid or invalid bytes)
		# output:		($v0, 1 if all valid, 0 if not)
		jal IsCandidate

		# load variables from stack
		lw $ra, 0($sp)		# load return address
		lw $a0, 4($sp)		# load init EP address
		lw $a1, 8($sp)		# load decrypted address
		lw $a2, 12($sp)		# load key K
		addi $sp, $sp, 16
		jr $ra
	endMsg:

		sw $t0, 0($a1)		# NULL terminate decrypted string
		li $v0, 1					# "is valid"
		li $v1, 0					# "no carry"
		jr $ra
	invalid:
		li $v0, 0
		li $v1, 0
		# load variables from stack
		lw $ra, 0($sp)		# load return address
		lw $a0, 4($sp)		# load init EP address
		lw $a1, 8($sp)		# load decrypted address
		sw $a2, 12($sp)		# load key K
		addi $sp, $sp, 16
		jr $ra

	# terminate program
	li $v0,10
	syscall
