#include <iostream>
#include "cpp_hal_extended.hpp"

// float foo::bar::MyHAL::simple_func(int a, float b) {
//   printf("%d\n",a);
//   return b;
// }

int foo::bar::MyHAL::class_arg(foo::bar::InternalClass *a,
                               foo::bar::InternalClass *b)
{
  a->i1 = b->i1;
  a->l1 = b->l1;
  return 0;
}

int foo::bar::MyHAL::class_ptr(foo::bar::InternalClass *a)
{
  a->i1 = 5;
  a->l1 = -1;
  return 0;
}

int main()
{
  foo::bar::MyHAL m;
  foo::bar::InternalClass c1;
  foo::bar::InternalClass c2;
  float ret;

  c1.i1 = 1;
  c1.l1 = 2;
  c2.i1 = 10;
  c2.l1 = 11;

  // ret = m.simple_func(7, 3.4f);
  m.class_arg(&c1, &c2);
  m.class_ptr(&c1);

  // std::cout << ret << std::endl;
  return 0;
}
