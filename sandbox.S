
.global patch_sandbox_start
.global patch_sandbox_end

.text 1
	
.align 0x1000

patch_sandbox_start:	
	retq				;
	.rept 64			;
	nopl   0x0(%rax,%rax,1)		;
	.endr				;
patch_sandbox_end:	

