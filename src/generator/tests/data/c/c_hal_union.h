struct InternalStruct {
    int a;
    union {
        long u_a;
	int u_b;
	char u_c;
    } b;
    long c;
};

struct MyStruct {
    int (*func_a)(struct InternalStruct *a);
    union {
        char u_a;
	int u_b;
    } a;
};
