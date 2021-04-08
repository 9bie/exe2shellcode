#include <Windows.h>
#include <windows.h>
#include <winternl.h>
#include <winhttp.h>
#include <string.h>
#include "api.h"


EXTERN_C VOID
mmLoaderSCStart();//这里用来表明shellcode的开始

void __stdcall Strat();//入口函数main

EXTERN_C VOID
mmLoaderSCEnd();//与开头对应的结尾