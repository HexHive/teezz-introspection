#include <stdint.h>
/*
 * Parsing should be able to handle all relevant primitive types.
 */
namespace foo {
namespace bar {

class MyClass {
  public:
    MyClass();
    ~MyClass();
    void bytes(uint8_t a, char b, int8_t c, int8_t &d, char* e);
    void shorts(uint16_t a, int16_t b, int16_t &c, uint16_t* d);
    void ints(uint32_t a, int b, int32_t c, int &d, uint32_t* e);
    void longs(uint64_t a, long b, int64_t c, long &d, int64_t* e);
    void bools(bool a, bool &b, bool* c);
    void floats(float a, float &b, float *c);
    void doubles(double a, double &b, double *c);
};
}
}
