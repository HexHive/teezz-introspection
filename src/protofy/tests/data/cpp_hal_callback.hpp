typedef void (*callback_func)(int a);

struct MyStruct {
    void (*func_a)(callback_func callback);
};
