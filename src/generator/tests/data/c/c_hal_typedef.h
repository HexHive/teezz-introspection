#include <stdint.h>

struct SomeStruct {
    uint32_t member_a;
    uint32_t member_b;
    uint64_t member_c;
};
typedef struct SomeStruct SomeStruct_t;

struct MyStruct {
    int (*myfunc)(SomeStruct_t *a, SomeStruct_t *b);
    SomeStruct_t *struct_ptr;
};
