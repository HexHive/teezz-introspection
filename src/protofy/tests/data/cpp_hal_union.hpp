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
    void (*func_a)(InternalStruct a);
    void (*func_b)(InternalStruct *a);
    union {
        char u_a;
	int u_b;
    } a;
};
