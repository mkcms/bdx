#include <stdint.h>

uint64_t foo;
uint64_t foo_;
int foo__; /* Should be at address 0x10 */

int uses_foo() { return foo; }

int c_function() { return foo; }

int a_name0;
int a_name1;
int a_name2;
int a_name3;
int a_name4;

char CamelCaseSymbol() { return ' '; }
