#include <iostream>
#include "cpp_hal_array.hpp"

int MyHAL::func_a(MyClass *a, MyClass *b) {
  a->a[0] = b->a[1];
  a->b->a[0] = b->b->a[1];
  return 0;
}

int MyHAL::func_b(InternalStruct *a, InternalStruct *b) {
  b->a[1] = a->a[1];
  b->b[2] = a->b[2];
  return 0;
}

int main () {
  class MyHAL m;
  struct InternalStruct is;
  struct InternalStruct is2;
  class MyClass c;

  c.a[0] = 1;
  c.a[1] = 2;
  c.b = &is;

  is.a[0] = 3;
  is.a[1] = 4;
  is.a[2] = 5;
  is.b[0] = 6;
  is.b[1] = 7;
  is.b[2] = 8;

  is2.a[0] = 13;
  is2.a[1] = 14;
  is2.a[2] = 15;
  is2.b[0] = 16;
  is2.b[1] = 17;
  is2.b[2] = 18;

  m.func_a(&c, &c);

  m.func_b(&is, &is2);

  std::cout << c.b->a[0] << std::endl;
  return 0;
}
