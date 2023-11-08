struct InternalStruct {
    long *a;
    short **b;
};

struct MyStruct {
    void (*func_a)(MyStruct *dev, int *a);
    void (*func_b)(MyStruct *dev, char **b);
    void (*func_c)(MyStruct *dev, InternalStruct &a);
};
