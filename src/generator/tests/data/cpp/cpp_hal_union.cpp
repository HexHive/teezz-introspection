#include <iostream>
#include "cpp_hal_union.hpp"

int MyHAL::func_a(InternalClass *a)
{
  a->a = a->b.u_a;
  a->b.u_c = 11;
  return 0;
}

int MyHAL::func_b(struct InternalStruct *a)
{
  a->a = a->b.u_b;
  a->b.u_a = a->c;
  return 0;
}

int main()
{
  MyHAL m;
  InternalClass ic;
  struct InternalStruct is;
  char *ch1 = "b\x00";

  ic.a = 1;
  ic.b.u_c = 0x98989898;
  ic.c = ch1;

  is.a = 2;
  is.b.u_a = 0x1337DEADBEEFCAFE;
  is.c = 3;

  m.func_a(&ic);
  m.func_b(&is);

  std::cout << ic.a << std::endl;
  return 0;
}
