namespace foo {
namespace bar {

class InternalClass {
  public:
    void setInt(int a);
    int getInt();

  private:
    int i1;
    long l1;
};

class MyHAL {
  public:
    MyHAL();
    ~MyHAL();
    void simple_func(int a, float b);
    void class_arg(InternalClass a, InternalClass &b);
    void class_ptr(InternalClass *a);

  private:
    long internal_long;
};
}
}
