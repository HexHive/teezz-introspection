#include <iostream>
#include "cpp_hal_parameter.hpp"

int foo::bar::baz::MyHAL::myfunc(foo::bar::baz::MyClass *a)
{
  a->val1 = 0;
  a->val2.i2 = 42;
  return 0;
}

int main()
{
  foo::bar::baz::MyHAL m;
  foo::bar::baz::MyClass mc;
  foo::bar::baz::InnerStruct s;
  s.i1 = 3;
  s.i2 = 11;
  mc.val1 = 1;
  mc.val2 = s;

  m.myfunc(&mc);

  std::cout << mc.val2.i2 << std::endl;
  return 0;
}
