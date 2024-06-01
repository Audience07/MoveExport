#include "head.h"



//打开文件，分配缓冲区，返回文件缓冲区指针
//如准备添加新节，请在最后一个参数填入新节的大小
LPVOID _OpenFile(IN const LPSTR str, IN size_t SizeOfNewSection) {
	size_t FileSize;
	FILE* pf = fopen(str, "rb");
	if (!pf) {
		perror("打开文件失败");
		return NULL;
	}
	fseek(pf, 0, SEEK_END);
	FileSize = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	LPVOID FileBuffer = malloc((FileSize+SizeOfNewSection));
	if (!FileBuffer) {
		printf("分配空间失败\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}

	fread(FileBuffer, 1, FileSize, pf);
	if (!FileBuffer) {
		printf("读取内存失败\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}
	fclose(pf);
	return FileBuffer;

}

LPVOID _vOpenFile(IN const LPSTR str, IN size_t SizeOfNewSection) {
	size_t FileSize;
	FILE* pf = fopen(str, "rb");
	if (!pf) {
		perror("打开文件失败");
		return NULL;
	}
	fseek(pf, 0, SEEK_END);
	FileSize = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	LPVOID FileBuffer = VirtualAlloc(NULL, FileSize + SizeOfNewSection, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//((FileSize + SizeOfNewSection));
	if (!FileBuffer) {
		printf("分配空间失败\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}

	fread(FileBuffer, 1, FileSize, pf);
	if (!FileBuffer) {
		printf("读取内存失败\n");
		fclose(pf);
		free(FileBuffer);
		return 0;
	}
	fclose(pf);
	return FileBuffer;

}





//读取文件标识，存储到FileSign结构中，返回节表数量
size_t _ReadData(LPVOID FileBuffer, struct FileSign* FileSign) {
	FileSign->MZHeader = *(WORD*)((char*)FileBuffer);
	if (FileSign->MZHeader != 0x5a4d) {
		return 0;
	}
	//定位指针
	FileSign->NTHeader = (char*)((char*)FileBuffer + (*(DWORD*)((char*)FileBuffer + 0x3C)));
	FileSign->PEHeader = (char*)((char*)FileSign->NTHeader + 0x4);
	FileSign->OptionalHeader = (char*)((char*)FileSign->NTHeader + 0x18);

	//PE头
	FileSign->Machine = *(WORD*)((char*)FileSign->PEHeader);
	FileSign->NumberOfSection = *(WORD*)((char*)FileSign->PEHeader + 0x2);
	FileSign->SizeOfOptionHeader = *(WORD*)((char*)FileSign->PEHeader + 0x10);

	//可选PE头
	FileSign->Magic = *(WORD*)((char*)FileSign->OptionalHeader);
	FileSign->EntryPoint = *(DWORD*)((char*)FileSign->OptionalHeader + 0x10);
	FileSign->ImageBase = *(DWORD*)((char*)FileSign->OptionalHeader + 0x1C);
	FileSign->SectionAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x20);
	FileSign->FileAlignment = *(DWORD*)((char*)FileSign->OptionalHeader + 0x24);
	FileSign->SizeOfImage = *(DWORD*)((char*)FileSign->OptionalHeader + 0x38);
	FileSign->SizeOfHeaders = *(DWORD*)((char*)FileSign->OptionalHeader + 0x3C);

	//返回节表数量
	return 1;
}






//读取节表关键字段
void _ReadSectionTable(OUT struct SectionTable* pSectionTable,IN struct FileSign* pFileSign) {
	for (int i = 0; i < pFileSign->NumberOfSection;i++, pSectionTable++) {
		pSectionTable->Point = (char*)((char*)pFileSign->OptionalHeader + pFileSign->SizeOfOptionHeader + (i * 0x28));
		memcpy(pSectionTable->name, pSectionTable->Point, 8);
		pSectionTable->VirtualSize = *(DWORD*)((char*)pSectionTable->Point + 0x8);
		pSectionTable->VirtualAddress = *(DWORD*)((char*)pSectionTable->Point + 0xC);
		pSectionTable->SizeOfRawData = *(DWORD*)((char*)pSectionTable->Point + 0x10);
		pSectionTable->PointToRawData = *(DWORD*)((char*)pSectionTable->Point + 0x14);
		pSectionTable->Characteristics = *(DWORD*)((char*)pSectionTable->Point + 0x24);
	}
}


//将缓冲区的文件读取到分配的可执行可读写内存里
LPVOID _vFileBuffer(IN LPVOID FileBuffer, IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable) {
	LPVOID vFileBuffer = VirtualAlloc(NULL, pFileSign->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!vFileBuffer) {
		return NULL;
	}
	memset(vFileBuffer, 0, pFileSign->SizeOfImage);
	memcpy(vFileBuffer, FileBuffer, pFileSign->SizeOfHeaders);
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		memcpy(((char*)vFileBuffer + pSectionTable->VirtualAddress), ((char*)FileBuffer + pSectionTable->PointToRawData), pSectionTable->SizeOfRawData);
		pSectionTable++;
	}
	return vFileBuffer;

}


//跳转至EntryPoint运行
//void _Run(IN struct FileSign* pFileSign, IN LPVOID vFileBuffer) {
//	DWORD EntryPoint = (char*)vFileBuffer + pFileSign->EntryPoint;
//	_asm{
//		mov eax, EntryPoint;
//		jmp eax;
//	}
//
//}



//返回代码节数
size_t _FindCodeSection(IN struct FileSign* pFileSign,IN struct SectionTable* pSectionTable) {
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		if ((pFileSign->EntryPoint > pSectionTable->VirtualAddress) && (pFileSign->EntryPoint < (pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData))) {
			return i;
		}
		pSectionTable++;
	}
}


//不可复用,将shellcode写入代码段结尾
void _WriteShellCodeToIdleArea(OUT LPVOID vFileBuffer,IN struct FileSign* pFileSign,IN struct SectionTable* pSectionTable,IN char* shellcode , IN size_t SizeOfCode) {
	//判断代码节
	size_t n = _FindCodeSection(pFileSign, pSectionTable);
	pSectionTable += n;

	
	//判断剩余空间是否够填入shellcode
	LPVOID BeginCode = ((char*)vFileBuffer + pSectionTable->VirtualAddress + pSectionTable->VirtualSize);
	if (SizeOfCode >= ((DWORD)vFileBuffer + (pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData) - (DWORD)BeginCode)) {
		printf("代码段剩余空间不足\n");
		return;
	}

	//填写shellcode
	memcpy(BeginCode, shellcode, SizeOfCode);


	//跳转根据ImageBuffer计算
	//修正call		FunctionAddress-(BeginCode+Push+5-ImageBuffer+ImageBase)	MessageBoxA在内存中的偏移
	LPVOID CallOffsetAddr = (char*)BeginCode + 0x8 + 0x1;
	*(DWORD*)CallOffsetAddr = (DWORD)MessageBoxA - ((DWORD)CallOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正jmp		OEP-(BeginCode+Push+Call+Jmp-ImageBuffer+ImageBase)			OEP在内存中的偏移
	LPVOID JmpOffsetAddr = (DWORD)CallOffsetAddr + 0x4 + 0x1;
	*(DWORD*)JmpOffsetAddr = (pFileSign->EntryPoint + pFileSign->ImageBase) - ((DWORD)JmpOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正OEP
	//EntryPoint 代码起始的偏移
	LPVOID pOEP = (DWORD)vFileBuffer + (*(DWORD*)((DWORD)vFileBuffer + 0x3C)) + (0x18 + 0x10);
	*(DWORD*)pOEP = (DWORD)BeginCode - (DWORD)vFileBuffer;

}


//把Shellcode写入新分配的节中
void _WriteShellCodeToNewSection(OUT LPVOID vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, IN LPSTR ShellCode, IN size_t SizeOfShellcode) {

	//定位新节的位置
	pSectionTable += pFileSign->NumberOfSection - 1;
	LPVOID pNewSection = (DWORD)vFileBuffer + pSectionTable->VirtualAddress;

	//全部填0
	memset(pNewSection, 0, pSectionTable->SizeOfRawData);

	//CopyShellcode
	memcpy(pNewSection, ShellCode, SizeOfShellcode);

	//跳转根据ImageBuffer计算
	//修正call		FunctionAddress-(BeginCode+Push+5-ImageBuffer+ImageBase)	MessageBoxA在内存中的偏移
	LPVOID CallOffsetAddr = (char*)pNewSection + 0x8 + 0x1;
	*(DWORD*)CallOffsetAddr = (DWORD)MessageBoxA - ((DWORD)CallOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正jmp		OEP-(BeginCode+Push+Call+Jmp-ImageBuffer+ImageBase)			OEP在内存中的偏移
	LPVOID JmpOffsetAddr = (DWORD)CallOffsetAddr + 0x4 + 0x1;
	*(DWORD*)JmpOffsetAddr = (pFileSign->EntryPoint + pFileSign->ImageBase) - ((DWORD)JmpOffsetAddr + 0x4 - (DWORD)vFileBuffer + pFileSign->ImageBase);

	//修正OEP
	//EntryPoint 代码起始的偏移
	LPVOID pOEP = (DWORD)vFileBuffer + (*(DWORD*)((DWORD)vFileBuffer + 0x3C)) + (0x18 + 0x10);
	*(DWORD*)pOEP = (DWORD)pNewSection - (DWORD)vFileBuffer;
}




//写入新的节，需传入ImageBuffer，Header头，节表数据，新节的名字
//已重写
LPVOID _AddNewSection(OUT LPVOID FileBuffer,IN LPCSTR SectionName,IN size_t SizeOfSection) {
	//获取PE信息
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + DosHeader->e_lfanew);
	if (NTHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-]_AddNewSection:不是有效的PE头\n");
		return NULL;
	}
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)&NTHeader->OptionalHeader + NTHeader->FileHeader.SizeOfOptionalHeader);

	//判断空间是否足够
	PIMAGE_SECTION_HEADER NewSectionHeader = SectionHeader + NTHeader->FileHeader.NumberOfSections;
	BOOL Judge = FALSE;
	for (int i = 0; i < 80; i++) {
		if ((*(BYTE*)((DWORD)NewSectionHeader + i))) {
			printf("[-]_AddNewSection:节表空间不足或存有其它数据\n");
			Judge = TRUE;
			break;
		}
	}
	//将NT头往前挪
	if (Judge) {
		DosHeader->e_lfanew = 0x40;
		NTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + DosHeader->e_lfanew);
		SectionHeader = (DWORD)&NTHeader->OptionalHeader + NTHeader->FileHeader.SizeOfOptionalHeader;
		NewSectionHeader = SectionHeader + NTHeader->FileHeader.NumberOfSections;
		printf("[+]_AddNewSection:NTHeader移至%x\n", NTHeader);
		//再次判断空间是否充足
		for (int i = 0; i < 80; i++) {
			if ((*(BYTE*)((DWORD)NewSectionHeader + i))) {
				printf("[-]_AddNewSection:节表空间依旧不足或存有其它数据\n");
				Judge = TRUE;
				break;
			}
		}
		if (Judge) {
			return NULL;
		}
	}

	//修改NumberOfSection
	NTHeader->FileHeader.NumberOfSections += 1;
	printf("[+]_AddNewSection:节表数量0x%x->0x%x\n", NTHeader->FileHeader.NumberOfSections-1, NTHeader->FileHeader.NumberOfSections);

	//写入新的节表
	memcpy(NewSectionHeader, SectionHeader, sizeof(IMAGE_SECTION_HEADER));
	printf("[+]_AddNewSection:地址:0x%x\n", NewSectionHeader);
	memset(NewSectionHeader, 0, 0x8);
	memcpy(NewSectionHeader, SectionName, 0x8);
	printf("[+]_AddNewSection:名字:%s\n", NewSectionHeader->Name);
	NewSectionHeader->Misc.VirtualSize = SizeOfSection;
	printf("[+]_AddNewSection:VirtualSize:0x%x\n", NewSectionHeader->Misc.VirtualSize);
	NewSectionHeader->VirtualAddress = (NewSectionHeader - 1)->VirtualAddress + (NewSectionHeader - 1)->SizeOfRawData;
	//NewSectionHeader->VirtualAddress = (NewSectionHeader - 1)->VirtualAddress + (((NewSectionHeader - 1)->SizeOfRawData > (NewSectionHeader - 1)->Misc.VirtualSize) ? (NewSectionHeader - 1)->SizeOfRawData : (NewSectionHeader - 1)->Misc.VirtualSize);
	printf("[+]_AddNewSection:VritualAddress:0x%x\n", NewSectionHeader->VirtualAddress);
	NewSectionHeader->SizeOfRawData = SizeOfSection;
	printf("[+]_AddNewSection:SizeOfRawData:0x%x\n", NewSectionHeader->SizeOfRawData);
	NewSectionHeader->PointerToRawData = (NewSectionHeader - 1)->PointerToRawData + (NewSectionHeader - 1)->SizeOfRawData;
	//NewSectionHeader->PointerToRawData = (NewSectionHeader - 1)->PointerToRawData + (((NewSectionHeader - 1)->SizeOfRawData > (NewSectionHeader - 1)->Misc.VirtualSize) ? (NewSectionHeader - 1)->SizeOfRawData : (NewSectionHeader - 1)->Misc.VirtualSize);
	printf("[+]_AddNewSection:PointerToRawData:0x%x\n", NewSectionHeader->PointerToRawData);
	NewSectionHeader->Characteristics |= (NewSectionHeader - 1)->Characteristics;
	printf("[+]_AddNewSection:Characteristics:0x%x\n", NewSectionHeader->Characteristics);

	//初始化节
	memset((DWORD)FileBuffer + NewSectionHeader->PointerToRawData, 0, NewSectionHeader->SizeOfRawData);
	
	return NewSectionHeader;

}




//释放ImageBuffer
//将ImageBuffer还原为FileBuffer
size_t _NewBuffer(IN LPVOID *vFileBuffer, IN struct SectionTable* pSectionTable, IN struct FileSign* pFileSign, IN size_t SizeOfCode,OUT LPVOID* NewBuffer) {

	pSectionTable += pFileSign->NumberOfSection-1;
	size_t FileSize = pSectionTable->PointToRawData + pSectionTable->SizeOfRawData;
	pSectionTable -= pFileSign->NumberOfSection - 1;
	//分配内存
	*NewBuffer = malloc(FileSize);
	if (!*NewBuffer) {
		printf("分配内存失败\n");
		free(*NewBuffer);
		return NULL;
	}
	memset(*NewBuffer, 0, FileSize);
	//copyPE头
	memcpy(*NewBuffer, *vFileBuffer, pFileSign->SizeOfHeaders);

	DWORD CodeSection = _FindCodeSection(pFileSign, pSectionTable);

	//循环copy节表
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		/*if (i == CodeSection) {
			pSectionTable->VirtualSize += SizeOfCode;
		}*/
		memcpy((DWORD)*NewBuffer + pSectionTable->PointToRawData, (DWORD)*vFileBuffer + pSectionTable->VirtualAddress, pSectionTable->SizeOfRawData);
		pSectionTable++;
	}
	//分配完NewBuffer后释放vFileBuffer
	VirtualFree(*vFileBuffer, pFileSign->SizeOfImage, MEM_COMMIT | MEM_RESERVE);
	*vFileBuffer = NULL;


	return FileSize;
}



//将NewBuffer存盘
void _SaveFile(IN LPVOID Buffer, IN LPSTR New_FilePATH) {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Buffer;
	PIMAGE_NT_HEADERS NTHeader = (DWORD)Buffer + DosHeader->e_lfanew;
	PIMAGE_SECTION_HEADER SectionHeader = (DWORD)&NTHeader->OptionalHeader + NTHeader->FileHeader.SizeOfOptionalHeader;
	SectionHeader += (NTHeader->FileHeader.NumberOfSections - 1);

	DWORD SizeOfBuffer = SectionHeader->PointerToRawData + SectionHeader->SizeOfRawData;
	FILE* pf = fopen(New_FilePATH, "wb");
	if (!pf) {
		perror("[-]创建文件失败\n");
		return;
	}
	if (!fwrite(Buffer, SizeOfBuffer, 1, pf)) {
		perror("[]-写入失败\n");
		fclose(pf);
		return;
	}
	printf("[+]存盘成功\n");
	fclose(pf);
}




//输出PE结构关键字段
void _OutputPEData(IN struct FileSign* pFileSign, IN struct SectionTable* pSectionTable) {
	printf("**********************************************************\n");
	printf("PE头:\n\n");
	//输出PE头
	printf("Machine:0x%x\n", pFileSign->Machine);
	printf("NumberOfSection:0x%x\n", pFileSign->NumberOfSection);
	printf("SizeOfOptionHeader:0x%x\n\n", pFileSign->SizeOfOptionHeader);

	//输出可选PE头
	printf("可选PE头:\n\n");
	printf("Magic:0x%x\n", pFileSign->Magic);
	printf("EntryPoint:0x%x\n", pFileSign->EntryPoint);
	printf("ImageBase:0x%x\n", pFileSign->ImageBase);
	printf("SectionAlignment:0x%x\n", pFileSign->SectionAlignment);
	printf("FileAlignment:0x%x\n", pFileSign->FileAlignment);
	printf("SizeOfImage:0x%x\n", pFileSign->SizeOfImage);
	printf("SizeOfHeaders:0x%x\n\n", pFileSign->SizeOfHeaders);

	printf("节表:\n\n");
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		printf("name:%s\n", pSectionTable->name);
		printf("VirtualSize:0x%x\n", pSectionTable->VirtualSize);
		printf("VirtualAddress:0x%x\n", pSectionTable->VirtualAddress);
		printf("SizeOfRawData:0x%x\n", pSectionTable->SizeOfRawData);
		printf("PointToRawData:0x%x\n", pSectionTable->PointToRawData);
		printf("Characteristics:0x%x\n\n", pSectionTable->Characteristics);
		pSectionTable++;
	}
	printf("**********************************************************\n");
	system("pause");
}


//计算文件对齐，返回对齐后的大小
size_t _MemoryAlign(size_t FileSize, size_t Align) {
	size_t n = FileSize / Align;
	if (FileSize % Align > 1) {
		n += 1;
	}
	return n * Align;
}



//将节合并为一个
void _Mergesection(LPVOID vFileBuffer, struct FileSign* pFileSign,struct SectionTable* pSectionTable,LPSTR SectionName) {
	LPVOID pNumberOfSection = (WORD*)((DWORD)vFileBuffer + *(DWORD*)((DWORD)vFileBuffer + 0x3C) + 0x6);
	*(WORD*)pNumberOfSection = 1;

	//定位节表
	LPVOID BeginSection = (DWORD)vFileBuffer + *(DWORD*)((DWORD)vFileBuffer + 0x3c) + 0x18 + pFileSign->SizeOfOptionHeader;

	//更改节的名字
	memcpy(BeginSection, SectionName, 8);


	//定位到原最后一个节的位置
	pSectionTable += pFileSign->NumberOfSection - 1;
	

	//更改VirtualSize
	LPVOID pVirtualSize = (DWORD)BeginSection + 0x8;
	*(DWORD*)pVirtualSize = pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData - _MemoryAlign(pFileSign->SizeOfHeaders, pFileSign->SectionAlignment);

	//更改SizeOfRawData
	LPVOID pSizeOfRawData = (DWORD)BeginSection + 0x10;
	*(DWORD*)pSizeOfRawData = pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData - _MemoryAlign(pFileSign->SizeOfHeaders, pFileSign->SectionAlignment);
	

}



//为最后一个节扩容
void _ExpansionSection(OUT LPVOID FileBuffer,IN struct FileSign* pFileSign,IN struct SectionTable* pSectionTable,IN size_t ExpansionSize) {

	//修改SizeOfImage
	LPVOID pSizeOfImage = (DWORD)FileBuffer + *(DWORD*)((DWORD)FileBuffer + 0x3C) + 0x18 + 0x38;
	*(DWORD*)pSizeOfImage += ExpansionSize;


	//定位最后一个节
	pSectionTable += pFileSign->NumberOfSection - 1;
	

	//修改VirtualSize
	LPVOID pVirtualSize = (DWORD)pSectionTable->Point + 0x8;
	*(DWORD*)pVirtualSize += ExpansionSize;

	//修改SizeOfRawData
	LPVOID pSizeOfRawData = (DWORD)pSectionTable->Point + 0x10;
	*(DWORD*)pSizeOfRawData += ExpansionSize;



}

DWORD _FindRVASection(LPVOID FileBuffer, DWORD RVA,struct FileSign* pFileSign,struct SectionTable* pSectionTable) {
	for (int i = 0; i < pFileSign->NumberOfSection; i++) {
		if (RVA >= pSectionTable->VirtualAddress && RVA < (pSectionTable->VirtualAddress + pSectionTable->SizeOfRawData)) {
			return i;
		}
		pSectionTable++;
	}
}


//已重写
DWORD _RVAToFOA(LPVOID FileBuffer,DWORD RVA) {
	
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + DosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)&NTHeader->OptionalHeader + NTHeader->FileHeader.SizeOfOptionalHeader);

	//定位所在节
	int i;
	for (i = 0; i < NTHeader->FileHeader.NumberOfSections - 1; i++) {
		if (RVA >= SectionHeader[i].VirtualAddress && RVA < SectionHeader[i + 1].VirtualAddress)
			break;
	}
	SectionHeader += i;
	//算出偏移
	DWORD Offset = RVA - SectionHeader->VirtualAddress;
	return SectionHeader->PointerToRawData + Offset;

}

DWORD _FOAToRVA(LPVOID FileBuffer, DWORD FOA) {
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + DosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)&NTHeader->OptionalHeader + NTHeader->FileHeader.SizeOfOptionalHeader);

	//定位所在节
	int i;
	for (i = 0; i < NTHeader->FileHeader.NumberOfSections - 1; i++) {
		if (FOA >= SectionHeader[i].PointerToRawData && FOA < SectionHeader[i + 1].PointerToRawData)
			break;
	}
	SectionHeader += i;
	//算出偏移
	DWORD Offset = FOA - SectionHeader->PointerToRawData;
	return SectionHeader->VirtualAddress + Offset;
}


//参数为FileBuffer，要寻找的函数的名字，返回函数在FileBuffer中的地址
LPVOID _GetFunctionAddrByName(LPVOID FileBuffer, LPSTR FunctionName) {

	//读取PE关键字段
	struct FileSign pFileSign;
	_ReadData(FileBuffer, &pFileSign);

	//读取节表关键字段
	struct SectionTable* pSectionTable = malloc((sizeof(pSectionTable)) * (pFileSign.NumberOfSection));
	if (!pSectionTable) {
		printf("pSectionTable分配失败\n");
		return NULL;
	}
	_ReadSectionTable(pSectionTable, &pFileSign);


	//获取导出表的FOA
	DWORD ExportTable_RVA = *(DWORD*)((DWORD)pFileSign.OptionalHeader + pFileSign.SizeOfOptionHeader - (8 * 16));
	DWORD ExportTable_FOA = _RVAToFOA(FileBuffer, ExportTable_RVA);
	LPVOID ExportTable = (DWORD)FileBuffer + ExportTable_FOA;


	//获取导出表名字个数
	DWORD NumberOfName = *(DWORD*)((DWORD)ExportTable + 0x18);


	//函数地址表
	LPVOID pAddrTable = (DWORD)ExportTable + 0x1C;
	DWORD pAddrTable_FOA = _RVAToFOA(FileBuffer, *(DWORD*)pAddrTable);
	DWORD* AddrTable = pAddrTable_FOA + (DWORD)FileBuffer;

	//函数名称表
	LPVOID pNameTable = (DWORD)ExportTable + 0x20;
	DWORD pNameTable_FOA = _RVAToFOA(FileBuffer, *(DWORD*)pNameTable);
	DWORD* NameTable = pNameTable_FOA + (DWORD)FileBuffer;
	//函数序号表
	LPVOID pNumberTable = (DWORD)ExportTable + 0x24;
	DWORD pNumberTable_FOA = _RVAToFOA(FileBuffer, *(DWORD*)pNumberTable);
	WORD* NumberTable = pNumberTable_FOA + (DWORD)FileBuffer;


	//循环对比名称，并以i当作索引
	int i = 0;
	for (i = 0; i < NumberOfName; i++) {
		LPSTR Name = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, *(DWORD*)(NameTable));
		if (!(strcmp(Name, FunctionName))) {
			break;
		}
		NameTable++;
	}
	//在函数名称个数内没有找到相对应的名字时,返回NULL
	if (i > NumberOfName-1) {
		return NULL;
	}
	

	//使用索引寻找序号
	NumberTable += i;
	WORD FunctionNumber = *(NumberTable);

	//返回函数地址
	AddrTable += FunctionNumber;
	LPVOID FunctionAddr = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, *AddrTable);
	return FunctionAddr;
	

}

//读取重定位表
void _PrintReloc(LPVOID FileBuffer) {

	//读取PE结构
	struct FileSign FileSign1;
	_ReadData(FileBuffer, &FileSign1);

	//读取节表
	struct SectionTable* pSectionTable = malloc(sizeof(pSectionTable) * FileSign1.NumberOfSection);
	_ReadSectionTable(pSectionTable, &FileSign1);


	//定位重定位表
	DWORD Reloc_RVA = *(DWORD*)((DWORD)FileSign1.OptionalHeader + FileSign1.SizeOfOptionHeader - (8 * 11));
	LPVOID Reloc = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, Reloc_RVA);
	

	//获取重定位表数据
	//DWORD VirtualAddr = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, *(DWORD*)(Reloc));
	DWORD VirtualAddr_FOA = (DWORD)FileBuffer + _RVAToFOA(FileBuffer,*(DWORD*)(Reloc));
	DWORD SizeOfBlock = *(DWORD*)((DWORD)Reloc + 0x4);
	WORD* Point = (WORD*)((DWORD)Reloc + 0x8);
	DWORD Temp;
	DWORD Offset;

	//循环打印需重定位的地址
	do {
		
		for (int i = 0; i < ((SizeOfBlock - 0x8) / 2); i++) {
			Temp = *(Point);
			if ((Temp & (0b1111000000000000)) == 0b0011000000000000) {
				Offset = (VirtualAddr_FOA + (Temp & 0b0000111111111111)) - (DWORD)FileBuffer;
				printf("Offset:0x%x\n", Offset);
			}
			Point++;
		}
		Reloc = (LPVOID)((DWORD)Reloc + SizeOfBlock);
		VirtualAddr_FOA = (DWORD)FileBuffer + _RVAToFOA(FileBuffer,*(DWORD*)(Reloc));
		SizeOfBlock = *(DWORD*)((DWORD)Point + 0x4);
		Point = (WORD*)((DWORD)Reloc + 0x8);
	} while (SizeOfBlock < 0xFFFF);

	return;
	
}

//将导出表挪入指定节，返回节的地址
LPVOID _MoveExport(IN LPVOID FileBuffer,IN LPCSTR SectionName) {
	//DOS头
	PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-]不是PE文件\n");
		return NULL;
	}
	printf("[+]_MoveExport:DOSHeader:0x%x\n", DOSHeader);

	//NT头
	PIMAGE_NT_HEADERS NTHeaders = (PIMAGE_NT_HEADERS)((DWORD)FileBuffer + DOSHeader->e_lfanew);
	if (NTHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-]缺少PE头\n");
		return NULL;
	}
	printf("[+]_MoveExport:NTHeaders:0x%x\n", NTHeaders);

	//打印节的数量
	DWORD NumberOfSection = NTHeaders->FileHeader.NumberOfSections;
	printf("[+]_MoveExport:节表的数量0x%x\n", NumberOfSection);


	//根据名字找出指定节
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)&NTHeaders->OptionalHeader + NTHeaders->FileHeader.SizeOfOptionalHeader);
	int i = 0;
	BOOL Judge = FALSE;
	for (i = 0; i < NTHeaders->FileHeader.NumberOfSections; i++) {
		if (!strcmp(SectionName, SectionHeader[i].Name)) {
			Judge = TRUE;
			break;
		}
	}
	if (!Judge) {
		printf("[-]_MoveExport:没有指定节\n");
		return NULL;
	}
	SectionHeader += i;

	


	//导出表位置
	if (!(DWORD)NTHeaders->OptionalHeader.DataDirectory->VirtualAddress) {
		printf("[-]_MoveExport:该文件没有导出函数\n");
		return NULL;
	}
	
	PIMAGE_EXPORT_DIRECTORY ExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD)FileBuffer + _RVAToFOA(FileBuffer, (DWORD)NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	
	printf("[+]_MoveExport:共0x%x个函数\n",ExportTable->NumberOfFunctions);
	if (ExportTable->Base > 0xFFFF) {
		printf("[-]_MoveExport:该动态链接库或许被加密\n");
		return NULL;
	}
	//拷贝名字

	//定位要拷贝的位置,2个指针,一个递加,一个待在原地,方便算大小
	LPVOID pNameOrigin = (DWORD)FileBuffer + SectionHeader->PointerToRawData;
	LPVOID pNamePoint = (DWORD)FileBuffer + SectionHeader->PointerToRawData;

	PDWORD pExportNames = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, ExportTable->AddressOfNames);
	LPCSTR Name;
	size_t Lenth;
	for (int i = 0; i < ExportTable->NumberOfNames; i++) {
		Name = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, *(DWORD*)pExportNames);
		Lenth = strlen(Name);
		memcpy(pNamePoint, Name, Lenth);
		(PBYTE)pNamePoint += Lenth+1;
		pExportNames++;
		printf("[+]_MoveExport:拷贝函数(%s)到%s节成功\n", Name, SectionName);
	}
	DWORD SizeOfName = (DWORD)pNamePoint - (DWORD)pNameOrigin;



	//拷贝序号表
	LPVOID pOrdinalsOrigin = (DWORD)pNamePoint;
	LPVOID pOrdinalsPoint = (DWORD)pOrdinalsOrigin;

	LPVOID OrdinalsTable = (DWORD)FileBuffer + _RVAToFOA(FileBuffer,ExportTable->AddressOfNameOrdinals);
	memcpy(pOrdinalsPoint, OrdinalsTable, ExportTable->NumberOfFunctions * sizeof(WORD));
	(WORD*)pOrdinalsPoint += ExportTable->NumberOfFunctions;
	DWORD SizeOfOrdinalsTable = (DWORD)pOrdinalsPoint - (DWORD)pOrdinalsOrigin;
	printf("[+]_MoveExport:挪动序号表成功,大小0x%x\n",SizeOfOrdinalsTable);


	//拷贝函数表
	LPVOID pFunctionOrigin = (DWORD)pOrdinalsPoint;
	LPVOID pFunctionPoint = (DWORD)pFunctionOrigin;

	LPVOID FunctionTable = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, ExportTable->AddressOfFunctions);
	memcpy(pFunctionPoint, FunctionTable, ExportTable->NumberOfFunctions * sizeof(DWORD));
	(DWORD*)pFunctionPoint += ExportTable->NumberOfFunctions;
	DWORD SizeOfFunctionTable = (DWORD)pFunctionPoint - (DWORD)pFunctionOrigin;
	printf("[+]_MoveExport:挪动函数表成功,大小0x%x\n", SizeOfFunctionTable);

	//拷贝导出表
	LPVOID pExportTableOrigin = (DWORD)pFunctionPoint;
	LPVOID pExportTablePoint = (DWORD)pExportTableOrigin;

	memcpy(pExportTablePoint, ExportTable, sizeof(IMAGE_EXPORT_DIRECTORY));
	(BYTE*)pExportTablePoint += sizeof(IMAGE_EXPORT_DIRECTORY);
	DWORD SizeOfExportTable = (DWORD)pExportTablePoint - (DWORD)pExportTableOrigin;
	printf("[+]_MoveExport:挪动导出表成功,大小0x%x\n", SizeOfExportTable);

	//拷贝名字表
	LPVOID pNameTableOrigin = (DWORD)pExportTablePoint;
	LPVOID pNameTablePoint = (DWORD)pNameTableOrigin;

	LPVOID NameTable = (DWORD)FileBuffer + _RVAToFOA(FileBuffer, ExportTable->AddressOfNames);

	memcpy(pNameTablePoint, NameTable, ExportTable->NumberOfNames * sizeof(DWORD));
	(DWORD*)pNameTablePoint += ExportTable->NumberOfNames;
	DWORD SizeOfNameTable = (DWORD)pNameTablePoint - (DWORD)pNameTableOrigin;
	printf("[+]_MoveExport:挪动名称表成功,大小0x%x\n", SizeOfNameTable);
	


	//修复EXPORT_ENTRY_ADDRESS
	(DWORD*)NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = _FOAToRVA(FileBuffer, (DWORD)pExportTableOrigin - (DWORD)FileBuffer);
	printf("[+]_MoveExport:修复入口DIRECTORY_ENTRY_EXPORT成功:0x%x\n", _FOAToRVA(FileBuffer, (DWORD)pExportTableOrigin - (DWORD)FileBuffer));

	//修复新的导出表
	PIMAGE_EXPORT_DIRECTORY NewExportTable = (DWORD)pExportTableOrigin;



	//修复导出表RVA
	NewExportTable->AddressOfNames = _FOAToRVA(FileBuffer, (DWORD)pNameTableOrigin - (DWORD)FileBuffer);
	printf("[+]_MoveExport:修复AddressOfNames成功:0x%x\n", _FOAToRVA(FileBuffer, (DWORD)pNameTableOrigin - (DWORD)FileBuffer));
	NewExportTable->AddressOfNameOrdinals = _FOAToRVA(FileBuffer, (DWORD)pOrdinalsOrigin - (DWORD)FileBuffer);
	printf("[+]_MoveExport:修复AddressOfNameOrdinals成功:0x%x\n", _FOAToRVA(FileBuffer, (DWORD)pOrdinalsOrigin - (DWORD)FileBuffer));
	NewExportTable->AddressOfFunctions = _FOAToRVA(FileBuffer, (DWORD)pFunctionOrigin - (DWORD)FileBuffer);
	printf("[+]_MoveExport:修复AddressOfFunctions成功:0x%x\n", _FOAToRVA(FileBuffer, (DWORD)pFunctionOrigin - (DWORD)FileBuffer));

	//修复名字表
	for (int i = 0; i < ExportTable->NumberOfNames; i++) {
		*(DWORD*)pNameTableOrigin = _FOAToRVA(FileBuffer, (DWORD)pNameOrigin - (DWORD)FileBuffer);
		(DWORD*)pNameTableOrigin += 1;
		(BYTE*)pNameOrigin += strlen(pNameOrigin) + 1;
		printf("[+]_MoveExport:修复名称表0x%x成功\n", _FOAToRVA(FileBuffer, (DWORD)pNameOrigin - (DWORD)FileBuffer));
	}



	return (DWORD)SectionHeader;
}


