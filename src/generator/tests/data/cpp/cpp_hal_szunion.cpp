#include <iostream>
#include <string.h>
#include <stdlib.h>
#include "cpp_hal_szunion.hpp"

int myfunc(struct MyStruct *a)
{
  memset(a->mBuffer.buf, '\x42', a->mSize);
  return 0;
}

int main()
{
  struct MyStruct s;
  s.mBuffer.buf = (char*)calloc(1, 16);
  s.mSize = 16;
  memset(s.mBuffer.buf, '\x41', s.mSize);

  struct MyStructFunc msf = { myfunc };
  msf.myfunc(&s);

  std::cout << s.mBuffer.buf << std::endl;
  return 0;
}

