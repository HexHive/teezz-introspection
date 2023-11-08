class InternalClass1 {
    char val2;
    long *val3;
};

class InternalClass2 {
    short *val1;
    double *val3;
};

class ComplexClass {
  private:
    InternalClass1 i11;
    InternalClass2 i2;
};

class MyHAL {
  public:
    MyHAL();
    ~MyHAL();
    void func_a(ComplexClass a, ComplexClass &b);
    void func_b(InternalClass1 &a, InternalClass2 *b);
};
