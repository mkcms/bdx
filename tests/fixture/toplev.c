const char top_level_symbol[64];

const char *const other_top_level_symbol = &top_level_symbol[0];

extern int uses_c_function();

int main(int argc, char **argv) { return uses_c_function(); }
