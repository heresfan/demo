#include "lib.h"

struct test_s
{
    int a;
    char b;
    long c;
};

void show_info(test_t *v)
{
    v = new test_t();
    v->a = 10;
    v->b = 11;
    v->c = 12;
}
