#include <iostream>
#include "cpp_hal_struct_array.hpp"

int MyHAL::func_b(MyClass *a, MyClass *b) {
  b->a[0] = a->a[1];
  return 0;
}

int main() {
  MyHAL m;
  MyClass mc1, mc2;
  struct InternalStruct is1, is2, is3, is4;

  is1.a[0] = 1;
  is1.a[1] = 2;
  is1.a[2] = 3;
  
  is2.a[0] = 11;
  is2.a[1] = 12;
  is2.a[2] = 13;

  is3.a[0] = 21;
  is3.a[1] = 22;
  is3.a[2] = 23;
  
  is4.a[0] = 31;
  is4.a[1] = 32;
  is4.a[2] = 33;

  mc1.a[0] = is1;
  mc1.a[1] = is2;

  mc2.a[0] = is3;
  mc2.a[1] = is4;

  m.func_b(&mc1, &mc2);

  std::cout << mc2.a[0].a[0] << std::endl;
  return 0;
}
