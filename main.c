#include "head.h"
LPSTR DLLPATH = "MyDLL.dll";
LPSTR NewDLLPATH = "MyDLL_New.dll";

int main() {
	//打开文件,获得FileBuffer
	LPVOID FileBuffer = _OpenFile(DLLPATH, 0x1000);

	//virtualSize可能会有溢出，OpenFile多分配的空间不够处理，使得触发中断

	

	//添加节
	LPVOID pNewSection = _AddNewSection(FileBuffer , ".Extra", 0x1000);
	if (!pNewSection) {
		return 0;
	}

	//移动导出表
	
	
	LPVOID pMvSection = _MoveExport(FileBuffer, ".Extra");
	if (!pMvSection) {
		printf("[-]main:_MoveExport错误\n");
		return 0;
	}

	_SaveFile(FileBuffer, NewDLLPATH);
	


}