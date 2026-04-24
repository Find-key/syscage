#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
    char buffer[64];
    const char *value = argc > 1 ? argv[1] : "hello";

    strcpy(buffer, value);
    puts(buffer);
    return (int)buffer[0];
}
