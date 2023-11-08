#include <iostream>
#include "cpp_hal_callback.hpp"

int MyHAL::func_b(callback_cb a, int b)
{
  a(b);
  return 0xcafebabe;
}

void callback(bool a)
{
  std::cout << "cb bool: " << a << std::endl;
}


int main()
{
  MyHAL m;

  MyHAL::callback_cb f(callback);
  m.func_b(f, 0xdeadbeef);

  std::cout << "Finished testcase" << std::endl;
  return 0;
}
