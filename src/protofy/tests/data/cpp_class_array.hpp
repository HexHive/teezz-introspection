
struct InternalStruct {
    int a[3];
    short b[3];
};

class MyClass {
    void func_c();
    char a[10];
    InternalStruct b[5];
};

class MyHAL {
  public:
    MyHAL();
    ~MyHAL();
    void func_a(int a[2], short b[6], long c);
    void func_b(MyClass a[3], MyClass &b, MyClass c);
    void func_c(InternalStruct a[4], InternalStruct &b, InternalStruct c);
};
