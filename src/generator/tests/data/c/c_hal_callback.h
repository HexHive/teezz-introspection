typedef void (*callback_func)(int a);

struct MyStruct {
    int (*func_a)(callback_func callback);
};
