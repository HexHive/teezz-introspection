class InternalClass1 {
  private:
    int member_a;
    long member_b;
    char *member_c;
};

struct InternalStruct1 {
    InternalClass1 member_a;
    InternalClass1 *member_b;
    int member_c;
};

class InternalClass2 {
    InternalStruct1 member_a;
    InternalClass1 member_b;
    short member_c;
};

struct InternalStruct2 {
    InternalClass1 member_a;
    InternalClass2 member_b;
    InternalStruct1 member_c;
};

class Wrapper {
    InternalStruct2 *member_a;
    InternalClass1 member_b;
    InternalClass2 *member_c;
};

class MyHAL {
  public:
    MyHAL();
    ~MyHAL();
    void func_a(Wrapper a, Wrapper &b);
    long func_b(InternalStruct1 &a, InternalClass2 b);
    int func_c(InternalStruct2 a, InternalStruct2 &b);
};
