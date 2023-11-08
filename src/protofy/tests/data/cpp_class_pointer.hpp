class MyClass {
    short **a;
    char *b;
};

struct MyStruct {
    MyClass *a;
    int b;
};

class MyHAL {
    void func_a(int &a, long **b);
    void func_b(MyClass &a, MyClass **b);
    void func_c(MyStruct **a, MyStruct b);
};
