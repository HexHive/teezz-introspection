#include <iostream>
#include "cpp_hal_hierarchy.hpp"

int MyHAL::func_a(ComplexClass *a, ComplexClass *b) {
  a->i1.val1 = b->i1.val1;
  *(a->i1.val2) = 0xff;
  *((a->i2).val2) = *((b->i2).val2);
  return 0;
}

int MyHAL::func_b(InternalClass1 *a, InternalClass2 *b) {
  *(a->val2) = *(b->val1);
  return 0;
}

int main () {
  MyHAL m;
  ComplexClass a;
  ComplexClass b;
  InternalClass1 ic11;
  InternalClass1 ic12;
  InternalClass2 ic21;
  InternalClass2 ic22;

  long l1 = 5;
  short s1 = 2;
  int i1 = 3;

  ic11.val1 = 'a';
  ic11.val2 = &l1;
  ic21.val1 = &s1;
  ic21.val2 = &i1;

  long l2 = 10;
  short s2 = 4;
  int i2 = 6;

  ic12.val1 = 'b';
  ic12.val2 = &l2;
  ic22.val1 = &s2;
  ic22.val2 = &i2;

  a.i1 = ic11;
  a.i2 = ic21;
  b.i1 = ic12;
  b.i2 = ic22;

  m.func_a(&a, &b);
  m.func_b(&ic11, &ic21);

  std::cout << a.i1.val1 << std::endl;
  return 0;
}
