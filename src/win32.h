/* Zig x86 C-translation workarounds for mingw headers.
   Forward-declare CONTEXT/PCONTEXT/LPCONTEXT so Zig's C translator
   can parse struct fields and function params that reference them
   before the full struct definition in winnt.h. */
#if defined(__i386__) || defined(_M_IX86)
typedef struct _CONTEXT CONTEXT;
typedef CONTEXT *PCONTEXT;
typedef CONTEXT *LPCONTEXT;
#ifndef _ALLOCA_S_MARKER_SIZE
#define _ALLOCA_S_MARKER_SIZE sizeof(unsigned int)
#endif
#endif
#include <windows.h>
