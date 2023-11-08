struct InternalStruct {
    int a;
    union {
        long u_a;
	int u_b;
	char u_c;
    } b;
    long c;
};

class InternalClass {
    short a;
    union {
        char u_a;
	int *u_b;
	int u_c;
    } b;
    char *c;
};

class MyHAL {
    void func_a(InternalClass a);
    void func_b(InternalStruct a);
    union {
        char u_a;
	int u_b;
    } a;
};
