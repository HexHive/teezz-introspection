template <class T>
class MyTemplate {
    T value;
    public:
    MyTemplate(T value);
    ~MyTemplate();
    T templatefunc(int a, int b);
};

struct MyStruct{
    void myfunc (MyTemplate<int> & a);
    //void myfunc2(MyTemplate<int> a);
    MyTemplate<int> test;
};
