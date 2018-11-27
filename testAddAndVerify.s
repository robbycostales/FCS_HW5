        .data
DecryptStringSpace: .space 400 # 400 bytes of space, more than enough...

AVCorrect:        .asciiz "\nCorrect Assessment"
AVKeyName:       .asciiz " keyval "
AVFailLead:      .asciiz "Test "
AVFalsePos:        .asciiz ": failed with correct key\n"
AVFalseNeg:      .asciiz ": failed (says correct) with wrong key\n"
AVStartTest:     .asciiz "\nStarting Test "
NewLine:        .asciiz "\n"
AVDone:         .asciiz "\nALL DONE\n"



TestData:
        # format is good key, bad key, encode-phrase-len (in words), encode phrase
        .word 12, 25, 2, 0x433c3d3c, 0x433e3d3e, 0
        .word 17, 20, 6, 0x493e492f, 0x443e482f, 0x3c3e3c41, 0x33333d30, 0x48333330, 0x3041323e, 0
        .word 0, 0, 0


.text

main:
        la $t0, TestData
        li $t1, 0
        li $t4, 1
AddVerifyTestLoop:

        add $t2, $t0, $t1
        lw $t3, 0($t2)
        beq $t3, $zero, AddVerifyTestDone
        la $a0, AVStartTest
        li $v0, 4
        syscall
        move $a0, $t4
        li $v0, 1
        syscall
        la $a0, NewLine
        li $v0, 4
        syscall

        move $a2, $t3
        sll $a2, $a2, 8
        or $a2, $a2, $t3
        sll $a2, $a2, 8
        or $a2, $a2, $t3
        sll $a2, $a2, 8
        or $a2, $a2, $t3
        move $a0, $t2
        add $a0, $a0, 12
        la $a1, DecryptStringSpace
        sw $t0, -4($sp)
        sw $t1, -8($sp)
        sw $a0, -12($sp)
        sw $a1, -16($sp)
        sw $a2, -20($sp)
        sw $t2, -24($sp)
        sw $t4, -28($sp)

        addi $sp, $sp, -28
        jal AddAndVerify
        addi $sp, $sp, 28
        lw $t0, -4($sp)
        lw $t1, -8($sp)
        lw $a0, -12($sp)
        lw $a1, -16($sp)
        lw $a2, -20($sp)
        lw $t2, -24($sp)
        lw $t4, -28($sp)
        li $t3, 1
        beq $t3, $v0, AddVerifyNextCase

        la $a0, AVFailLead
        li $v0, 4
        syscall
        move $a0, $t4
        li $v0, 1
        syscall
        la $a0, AVKeyName
        li $v0, 4
        syscall
        lw $a0, 0($t2)
        li $v0, 1
        syscall
        la $a0, AVFalsePos
        li $v0, 4
        syscall


        ### Now try with bad key
AddVerifyNextCase:
        lw $t3, 4($t2)
        move $a2, $t3
        sll $a2, $a2, 8
        or $a2, $a2, $t3
        sll $a2, $a2, 8
        or $a2, $a2, $t3
        sll $a2, $a2, 8
        or $a2, $a2, $t3
        move $a0, $t2
        add $a0, $a0, 12
        la $a1, DecryptStringSpace
        sw $t0, -4($sp)
        sw $t1, -8($sp)
        sw $a0, -12($sp)
        sw $a1, -16($sp)
        sw $a2, -20($sp)
        sw $t2, -24($sp)
        sw $t4, -28($sp)

        addi $sp, $sp, -28
        jal AddAndVerify
        addi $sp, $sp, 28
        lw $t0, -4($sp)
        lw $t1, -8($sp)
        lw $a0, -12($sp)
        lw $a1, -16($sp)
        lw $a2, -20($sp)
        lw $t2, -24($sp)
        lw $t4, -28($sp)

        beq $zero, $v0, AddVerifyNextIter

        la $a0, AVFailLead
        li $v0, 4
        syscall
        move $a0, $t4
        li $v0, 1
        syscall
        la $a0, AVKeyName
        li $v0, 4
        syscall
        lw $a0, 4($t2)
        li $v0, 1
        syscall
        la $a0, AVFalseNeg
        li $v0, 4
        syscall

AddVerifyNextIter:
        addi $t4, $t4, 1
        lw $t3, 8($t2)
        sll $t3, $t3, 2
        add $t1, $t1, $t3
        addi $t1, $t1, 16
        j AddVerifyTestLoop

AddVerifyTestDone:
        la $a0, AVDone
        li $v0, 4
        syscall
        li $v0, 10
        syscall




        ############# Put Code for AddAndVerify, IsCandidate, WordDecrypt Here
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
        	lw $t0, 4($sp)			 # $t0 is current word
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
