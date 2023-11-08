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

namespace foo {
namespace bar {
namespace baz {

struct MyStruct{
    int (*myfuncptr)(const int a, const int b);
    int (*myfuncptr2)(const int a);
    struct ComplexStruct cs;
    uint64_t test;
};

class MyHAL {
  public:
    MyHAL();
    ~MyHAL();
    void myfunc2(struct MyStruct* a);
};

} // namespace foo
} // namespace bar
} // namespace baz
