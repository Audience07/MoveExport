#include "head.h"
LPSTR DLLPATH = "MyDLL.dll";
LPSTR NewDLLPATH = "MyDLL_New.dll";

int main() {
	//���ļ�,���FileBuffer
	LPVOID FileBuffer = _OpenFile(DLLPATH, 0x1000);
	if (!FileBuffer) {
		printf("[-]����Ƿ��и��ļ�\n");
		return 0;
	}

	//virtualSize���ܻ��������OpenFile�����Ŀռ䲻������ʹ�ô����ж�


	

	//��ӽ�
	LPVOID pNewSection = _AddNewSection(FileBuffer , ".Extra", 0x1000);
	if (!pNewSection) {
		return 0;
	}

	//�ƶ�������
	DWORD ExportSize = _MoveExportByAddr(FileBuffer, pNewSection);
	if (!ExportSize) {
		printf("[-]main:_MoveExport����\n");
		return 0;
	}


	DWORD RelocSize = _MoveReloc(FileBuffer, (DWORD)pNewSection + ExportSize);
	if (!RelocSize) {
		printf("[-]main:_MoveReloc����\n");
	}


	_SaveFile(FileBuffer, NewDLLPATH);
	


}