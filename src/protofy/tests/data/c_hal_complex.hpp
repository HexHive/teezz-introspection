#include<cstdint>

struct InnerStruct {
    uint32_t inner_member_a;
    uint32_t inner_member_b;
    uint32_t inner_member_c;
};

struct ComplexStruct {
    struct InnerStruct is;
    uint64_t member_a;
};

struct WrapperStruct {
    struct ComplexStruct cs;
    uint64_t test;
};

struct MyStruct{
    int (*myfuncptr)(ComplexStruct a, WrapperStruct b);
    int (*myfuncptr2)(WrapperStruct *a, InnerStruct *b);
    struct ComplexStruct cs;
    uint64_t test;
};

