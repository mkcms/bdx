#include <vector>

extern int foo;
int bar;
static int global_integer;

int cxx_function(std::vector<int>) { return foo + bar; }

char CppCamelCaseSymbol(const char *x) { return x[0]; }

extern "C" int c_function();

extern "C" {
int uses_c_function() { return c_function() + 1; }
}
