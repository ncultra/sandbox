#include <memory.h>
#include <stdarg.h>
#include <stdio.h>



int main(int argc, char **argv) 
{
	
	unsigned long long  data = 0xbeeef, hvabs = 0xfeeed, old_data;
	int i, loops, method;
	loops = strtol(argv[1], NULL, 10);
	method = strtol(argv[2], NULL, 10);

//	printf("hvabs: %llX data: %llX\n", hvabs, data);
	
	if(method == 1) {
		for(i = 0; i < loops; i++) {

			__atomic_exchange((unsigned long long *)&hvabs,
			      (unsigned long long *)&data,
			      (unsigned long long *)&data,
			      __ATOMIC_SEQ_CST);
//			printf("hvabs: %llX data: %llX\n", hvabs, data);
		}
			
	} else {
			for(i = 0; i < loops; i++) {
				memcpy(&old_data, &hvabs, sizeof(old_data));
				memcpy(&hvabs, &data, sizeof(hvabs));
				memcpy(&data, &old_data, sizeof(data));
			}
//			printf("hvabs: %llX data: %llX\n", hvabs, data);
		}



		
	return 0;
}
