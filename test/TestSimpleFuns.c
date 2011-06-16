#include <stdlib.h>
#include <stdio.h>

extern int gcd(int, int);
extern int add(int, int);
extern int fib(int);

int main(int argc, const char* argv[])
{
    int i;
    printf("add(3, 8)   -> %i\n", add(3, 8));
    printf("add(36, 81) -> %i\n", add(36, 81));
    printf("gcd(36, 81) -> %i\n", gcd(36, 81));
    for (i = 0; i < 20; i++) {
		printf("fib(%i) -> %i\n", i, fib(i));
	}
    
    return 0;
}
