#include <iostream>
#include "cpp_hal_callback.hpp"

// int MyHAL::func_a(CallbackClass *a, char b) {
//   b = 'a';
//   return 0;
// }

int MyHAL::func_b(callback_cb a, int b)
{
  b = 42;
  a(b);
  return 0;
}

int MyHAL2::func_b(callback_cb a, int b)
{
  b = 42;
  a(b);
  return 0;
}

// int MyHAL::func_c(struct CallbackStruct *a, long b) {
//   b = 1337;
//   return 0;
// }

void callback(bool a)
{
  a = true;
}

void callback2(bool b)
{
  b = false;
}

MyHalRefBase::~MyHalRefBase() {}

int main()
{
  MyHAL m;
  MyHAL2 m2;
  // struct CallbackStruct cs;
  // CallbackClass cc;

  // m.func_a(&cc, 'b');

  MyHAL2::callback_cb f(callback);
  m.func_b(f, 0);
  m2.func_b(f, 0);

  // m.func_c(&cs, 1);

  std::cout << "Finished testcase" << std::endl;
  return 0;
}
