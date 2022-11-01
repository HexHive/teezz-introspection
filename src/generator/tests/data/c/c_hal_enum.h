typedef enum {
    en_val_1 = 1,
    en_val_2 = 3,
    en_val_3 = 2 << 8,
    en_val_4 = 10 << 28,
} hal_enum;

struct MyStruct {
    int (*myfunc_a)(hal_enum a, int b);
};
