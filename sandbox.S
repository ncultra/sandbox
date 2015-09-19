
#include "sandbox_decls.h"

.global patch_sandbox_start
.global patch_sandbox_end

.text 
	
	.align 0x1000	       # align on page boundary

patch_sandbox_start: # remove the jmp when we can patch the sandbox
	jmp patch_sandbox_end 
	.fill SANDBOX_ALLOC_SIZE	
patch_sandbox_end:	# for testing only, jump to the end of the sandbox
	.align 2	
	retq  		# and return to the caller


