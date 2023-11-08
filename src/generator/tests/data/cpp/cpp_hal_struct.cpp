#include <iostream>
#include "cpp_hal_struct.hpp"

int MyHAL::func_a(Wrapper *a, Wrapper *b)
{
  a->member_b = b->member_b;
  return 0;
}

long MyHAL::func_b(struct InternalStruct1 *a, InternalClass2 *b)
{
  b->member_c += 1;
  b->member_a = *a;
  return 0;
}

int MyHAL::func_c(struct InternalStruct2 *a, InternalStruct2 *b)
{
  a->member_a.member_a = b->member_c.member_c;
  return 0;
}

int main()
{

  MyHAL m;
  InternalClass1 ic11, ic12;
  InternalClass2 ic21, ic22;
  struct InternalStruct1 is11, is12;
  struct InternalStruct2 is21, is22;
  Wrapper w1, w2;

  char *ch1 = "a";
  char *ch2 = "b";

  ic11.member_a = 1;
  ic11.member_b = 2;
  ic11.member_c = ch1;

  ic12.member_a = 3;
  ic12.member_b = 4;
  ic12.member_c = ch2;

  is11.member_a = ic11;
  is11.member_b = &ic11;
  is11.member_c = 5;

  is12.member_a = ic12;
  is12.member_b = &ic12;
  is12.member_c = 6;

  ic21.member_a = is11;
  ic21.member_b = ic11;
  ic21.member_c = 7;

  ic22.member_a = is12;
  ic22.member_b = ic12;
  ic22.member_c = 8;

  is21.member_a = ic11;
  is21.member_b = ic21;
  is21.member_c = is11;

  is22.member_a = ic12;
  is22.member_b = ic22;
  is22.member_c = is12;

  w1.member_a = &is21;
  w1.member_b = ic11;
  w1.member_c = &ic21;

  w2.member_a = &is22;
  w2.member_b = ic12;
  w2.member_c = &ic22;

  m.func_a(&w1, &w2);
  m.func_b(&is11, &ic22);
  m.func_c(&is21, &is22);

  std::cout << w1.member_b.member_a << std::endl;
  return 0;
}
