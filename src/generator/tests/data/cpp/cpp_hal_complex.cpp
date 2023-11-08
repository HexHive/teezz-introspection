#include <iostream>
#include "cpp_hal_complex.hpp"

int foo::bar::baz::MyHAL::myfunc(struct foo::bar::baz::MyStruct *a) {
  a->test = 4;
  a->cs.member_a = 6;
  a->cs.is.inner_member_a = -1;
  return 0;
}

int main() {
  foo::bar::baz::MyHAL m;
  struct foo::bar::baz::MyStruct s;
  struct ComplexStruct cs;
  struct InnerStruct is;
  is.inner_member_a = 10;
  is.inner_member_b = 11;
  is.inner_member_c = 12;
  cs.is = is;
  cs.member_a = 1;
  s.cs = cs;
  s.test = 2;

  m.myfunc(&s);

  std::cout << s.test << std::endl;

  return 0;
}
