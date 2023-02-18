#include<stdio.h>
extern int counter;

void init(void){
	frida_log("Hello from C");
	printf("sss");

}


void bump(int n){
	counter += n;
}

