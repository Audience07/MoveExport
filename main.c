#include "head.h"
LPSTR DLLPATH = "MyDLL.dll";
LPSTR NewDLLPATH = "MyDLL_New.dll";

int main() {
	//���ļ�,���FileBuffer
	LPVOID FileBuffer = _OpenFile(DLLPATH, 0x1000);

	//virtualSize���ܻ��������OpenFile�����Ŀռ䲻������ʹ�ô����ж�

	

	//��ӽ�
	LPVOID pNewSection = _AddNewSection(FileBuffer , ".Extra", 0x1000);
	if (!pNewSection) {
		return 0;
	}

	//�ƶ�������
	
	
	LPVOID pMvSection = _MoveExport(FileBuffer, ".Extra");
	if (!pMvSection) {
		printf("[-]main:_MoveExport����\n");
		return 0;
	}

	_SaveFile(FileBuffer, NewDLLPATH);
	


}