namespace foo {
namespace bar {

struct InnerStruct {
    int a[4];
    long b[6];
};

struct MyStruct {
    void (*func_a)(InnerStruct a, InnerStruct b);
    void (*func_b)(int a[2], long b);
};
}
}
