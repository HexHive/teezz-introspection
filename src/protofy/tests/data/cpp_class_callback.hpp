#include <functional>
class CallbackClass {
    void callback_func();
};

struct CallbackStruct {
    void (*callback)();
};

class MyHAL {
    void func_a(CallbackClass a, char b);
    using callback_cb = std::function<void(bool a)>;
    void func_b(callback_cb a, int b);
    void func_c(CallbackStruct a, long b);
};
