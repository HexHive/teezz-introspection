/*
 * Android's HALs before Android 8 were written in C.
 * These HAL definiton have an object-oriented design based on C structs.
 */

struct mystruct {

  int mymember;
  int (*myfunc)(int a, int b);
};
