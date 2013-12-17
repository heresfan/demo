#ifndef _TRACE_H_
#define _TRACE_H_

#include <cstdio>

#ifdef _DEBUG
#  define TRACE(formmat, ...) printf(formmat, ##__VA_ARGS__)
#else
#  define TRACE(formmat, ...)
#endif

#endif

