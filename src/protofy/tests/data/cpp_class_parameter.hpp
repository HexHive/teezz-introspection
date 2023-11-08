namespace foo {
namespace bar {
namespace baz {

struct InnerStruct{
    double i1;
    int i2;
};

class MyClass {
    int val1;
    struct InnerStruct val2;
  public:
    MyClass();
    ~MyClass();
    void myfunc(int a);
};

struct MyStruct{
    int (*myfuncptr)(const MyClass & b);
    int test;
};

} // namespace foo
} // namespace bar
} // namespace baz
