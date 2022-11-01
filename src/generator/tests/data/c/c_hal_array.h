
struct InnerStruct {
    int a[4];
    long b[6];
};

struct MyStruct {
    int (*func_a)(struct MyStruct *dev, struct InnerStruct *a, 
		   struct InnerStruct *b);
};
