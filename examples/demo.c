#include <stdio.h>

struct IntValue {
    int i;
    const char *s;
};

static const struct IntValue IntValues[] = {{123, "123"},{456, "456"}};

static void compare_structure(const struct IntValue *v1, const struct IntValue *v2)
{
    if (v1->i >= v2->i) {
        printf("%s >= %s\n", v1->s, v2->s);
    } else {
        printf("%s < %s\n", v1->s, v2->s);
    }
}

int main(int argc, char *argv[])
{
    if (argc == 1) {
        compare_structure(&IntValues[0], &IntValues[1]);
    } else {
        compare_structure(&IntValues[1], &IntValues[0]);
    }
    return 0;
}
