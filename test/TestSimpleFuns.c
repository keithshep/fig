#include <stdlib.h>
#include <stdio.h>

extern int gcd(int, int);
extern int add(int, int);
extern int fib(int);
extern int isEven(unsigned int);
extern int isOdd(unsigned int);
extern double power(double, int);
extern double distSqOf789();

int main(int argc, const char* argv[])
{
    int i;
    printf("add(3, 8)   = %i\n", add(3, 8));
    printf("add(36, 81) = %i\n", add(36, 81));
    printf("gcd(36, 81) = %i\n", gcd(36, 81));
    for (i = 0; i < 20; i++) {
        printf("\n");
        printf("fib(%i)        = %i\n", i, fib(i));
        printf("isEven(%i)     = %i\n", i, isEven(i));
        printf("isOdd(%i)      = %i\n", i, isOdd(i));
        printf("power(1.5, %i) = %f\n", i, power(1.5, i));
    }
    printf("distSqOf789() = %f\n", distSqOf789());
    
    return 0;
}
