struct InternalStruct {
    long *a;
    short **b;
};

struct MyStruct {
    int (*func_a)(struct MyStruct *dev, int *a);
    int (*func_b)(struct MyStruct *dev, int **b);
    int (*func_c)(struct MyStruct *dev, struct InternalStruct *a);
};
