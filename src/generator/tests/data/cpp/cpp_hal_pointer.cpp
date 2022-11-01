#include <iostream>
#include "cpp_hal_pointer.hpp"

int MyHAL::func_a(int *a, long **b)
{
  **b = *a;
  return 0;
}

int MyHAL::func_b(MyClass *a, MyClass **b)
{
  *b = a;
  return 0;
}

int MyHAL::func_c(struct MyStruct **a, MyStruct *b)
{
  **a = *b;
  return 0;
}

int main()
{
  MyHAL m;
  struct MyStruct s1, s2;
  MyClass c1, c2;

  int i = 5;
  long l = 10;
  long *lp = &l;
  char *ch1 = "a";
  char *ch2 = "b";
  short sh1 = 4;
  short sh2 = 6;
  short *sh1p = &sh1;
  short *sh2p = &sh2;

  c1.b = ch1;
  c2.b = ch2;
  c1.a = &sh1p;
  c2.a = &sh2p;

  s1.a = &c1;
  s2.a = &c2;
  s1.b = 1;
  s2.b = 2;

  MyClass *c2p = &c2;
  struct MyStruct *s1p = &s1;

  m.func_a(&i, &lp);
  m.func_b(&c1, &c2p);
  m.func_c(&s1p, &s2);

  std::cout << (*(s1p->a)).b << std::endl;
}
