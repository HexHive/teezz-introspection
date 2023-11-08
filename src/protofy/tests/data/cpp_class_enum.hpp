typedef enum {
    en_val_1 = 0,
    en_val_2 = 1,
    en_val_3 = 7,
    en_val_4 = 15 << 8,
    en_val_5 = 10 << 28,
} enum_hal;

class MyHAL {
  public:
    MyHAL();
    ~MyHAL();
    int myfunc(enum_hal en_val, long b);
};
