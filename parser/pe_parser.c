#define _CRT_SECURE_NO_WARNINGS
#include "pe_parser.h"
#include "../untils//file_tils.h"



static bool parser_initalized = false;

/*
@brief 初始化PE文件解析器

@return 初始化结果状态码


*/


analysis_result_t initialize_pe_parser(void) {
	//检查是否已经初始化
	if (parser_initalized)
	{

		return RESULT_SUCCESS;

	}
	//设置初始化标记

	parser_initalized = true;

	return RESULT_SUCCESS;


}
/*
@brief 清理PE文件解析器



*/


void clean_pe_parser(void)
{

	parser_initalized = false;
}



/*

@brief  解析PE文件,判断是否为PE结构
@param filename PE文件路径
@param pe_info 用于存储分析结构的报告结构体指针
@return  解析结果状态码





*/

analysis_result_t validate_pe_structure(const uint8_t* file_data, uint32_t file_size)
{

	//检查参数
	if (!file_data||file_size<sizeof(IMAGE_DOS_HEADER))
	{


		return RESULT_ERROR_INVALID_PE;
	}


	//获取DOS头指针
	const IMAGE_DOS_HEADER* dos_header = (const IMAGE_DOS_HEADER*)file_data;

	//检查DOS签名
	if (dos_header->e_magic!=IMAGE_DOS_SIGNATURE)
	{


		return RESULT_ERROR_INVALID_PE;
	}


	//验证NT头偏移有效性
	if (dos_header->e_lfanew>=file_size||dos_header->e_lfanew<sizeof(IMAGE_DOS_HEADER))
	{

		return RESULT_ERROR_INVALID_PE;

	}

//NT头是否超过文件大小
	if (dos_header->e_lfanew+sizeof(IMAGE_NT_HEADERS)>file_size)
	{

		return RESULT_ERROR_INVALID_PE;

	}
	//获取NT头指针
	const IMAGE_NT_HEADERS* nt_header = (const IMAGE_NT_HEADERS*)(file_data + dos_header->e_lfanew);


	//检查nt签名

	if (nt_header->Signature!=IMAGE_NT_SIGNATURE)
	{
		return RESULT_ERROR_INVALID_PE;


	}






	return RESULT_SUCCESS;
}
/*

@brief  解析Dos数据
@param  file_data   文件数据指针
@param dos_header   用于存储Dos信息结构体指针
@return  解析结果状态码





*/

analysis_result_t parse_dos_header(const uint8_t* file_data, IMAGE_DOS_HEADER* dos_header)
{
	//验证参数有效性
	if (!file_data||!dos_header)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}
	memcpy(dos_header, file_data, sizeof(IMAGE_DOS_HEADER));





	return RESULT_SUCCESS;
}
/*

@brief  解析NT数据
@param  file_data   文件数据指针
@param  nt_offset NT头在文件中的偏移量
@param NT_header 用于存储NT信息结构体指针
@return  解析结果状态码





*/analysis_result_t parse_nt_header(const uint8_t* file_data, uint32_t nt_offset,
	IMAGE_NT_HEADERS* nt_header)
{

	//验证参数有效性
	if (!file_data || !nt_header)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}
	memcpy(nt_header, file_data+nt_offset, sizeof(IMAGE_NT_HEADERS));

	return RESULT_SUCCESS;
}


/*

@brief  解析NT节数据
@param  file_data   文件数据指针
@param  file_size   文件大小
@param  nt_header_offset  NT头部在文件中的偏移量
@param NT_header 用于存储NT信息结构体指针
@param sections   用于存储节信息数组的指针
@param section_count  
@return  解析结果状态码





*/



analysis_result_t parse_section(const uint8_t* file_data, uint32_t file_size,
	uint32_t nt_header_offset, const IMAGE_NT_HEADERS* nt_headers,
	section_info_t** sections, uint16_t* section_count)
{
	//参数校验
	if (!file_data||file_size==0||!nt_headers||!sections||!section_count)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}
	//验证NT头部偏移量的有效性
	if (nt_header_offset>=file_size||nt_header_offset+sizeof(IMAGE_NT_HEADERS)>file_size)
	{


		return RESULT_ERROR_INVALID_PE;



	}

	//验证节区数量异常


	*section_count = nt_headers->FileHeader.NumberOfSections;

	if (*section_count==0)
	{
		*section_count = 0;
		printf("节区数量为0");
		return RESULT_ERROR_INVALID_PE;

	}
	if (*section_count>96)
	{

		return RESULT_ERROR_INVALID_PE;
	}



	//申请内存存储节区结构信息
	*sections = malloc(sizeof(section_info_t) * (*section_count));

	if (!*sections)
	{


		return RESULT_ERROR_MEMORY_ALLOCATION;
	}
	//计算节区在文件中的位置

	size_t section_offset = nt_header_offset + sizeof(DWORD)
		+ sizeof(IMAGE_FILE_HEADER) + nt_headers->FileHeader.SizeOfOptionalHeader;
	//验证节区位置是否正常

	size_t section_size = sizeof(IMAGE_SECTION_HEADER) * (*section_count);
	if (section_offset+section_size>file_size)
	{
		SAFE_FREE(*sections);
		return RESULT_ERROR_INVALID_PE;


	}
	//定位节区

	const IMAGE_SECTION_HEADER* section_headers = (const IMAGE_SECTION_HEADER*)(file_data + section_offset);


	//遍历节区

	for (size_t i=0;i<*section_count;i++)
	{
		section_info_t* section = &(*sections)[i];
		const IMAGE_SECTION_HEADER* header = &section_headers[i];
		memset(section->name, 0, IMAGE_SIZEOF_SHORT_NAME + 1);


		memcpy(section->name, header->Name, IMAGE_SIZEOF_SHORT_NAME);


		section->virtual_address = header->VirtualAddress;
		section->virtual_size = header->Misc.VirtualSize;
		section->raw_address = header->PointerToRawData;
		section->raw_size = header->SizeOfRawData;
		section->characteristics = header->Characteristics;

		section->is_executable = (header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		section->is_writable= (header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
		/*
		
		.text  读取 + 执行
		.data  读取 + 写入
		.rdata 只读 (Read-Only)
		.rsec  程序的图标、位图、菜单、对话框、字符串表、版本信息等  只读 (Read-Only)。
		.reloc  实现地址空间布局随机化（ASLR）安全机制的基础  通常为只读，
		
		
		image_scn_mem_execute
		image_scn_mem_write
		image_scn_mem_read
		
		

		
		*/



		if (header->PointerToRawData>0&&header->SizeOfRawData>0)
		{
			if (header->PointerToRawData < file_size && header->PointerToRawData + header->SizeOfRawData < file_size) {


				section->entropy = calcuate_entropy(file_data + header->PointerToRawData, header->SizeOfRawData);

			}
			else
			{
				section->entropy = 0.0;

			}



		}


	}






	return RESULT_SUCCESS;

}

/*

@brief 计算数据的信息熵
@param data 数据指针
@param size 数据大小
@return  计算得到的熵值

低(0.0)     数据有序可能是填充数据|重复数据|纯文本
中(4.0~6.0) 正常可执行的代码,通常在这个范围内
高(8.0)     数据随机 - 可能是加密|压缩|混淆|代码或数据



*/

double calcuate_entropy(const uint8_t* data, uint32_t size)
{
	//参数有效检查
	if (!data||size==0)
	{
		return 0;
	}

	//频率统计数组
	uint32_t byte_counts[256] = { 0 };

	__try {

		for (size_t i=0;i<size;i++)
		{

			byte_counts[data[i]]++;//0~255

		}


	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		
		return 0.0;

	}

	double entropy = 0.0;

	//0~255

	for (size_t i=0;i<256;i++)
	{
		//只处理实际出现的字节数

		if (byte_counts[i]>0)
		{

			double temp = (double)byte_counts[i] / size;

			entropy -= temp * log2(temp);


		}




	}



	return entropy;
}
/*

@brief 释放文件列表内存
@param  file_list 文件列表结构体指针







*/

void free_file_list(file_list_t* file_list)
{if (!file_list)
{
	return;
}
for (size_t i=0;i<file_list->count;i++)
{
	SAFE_FREE(file_list->file[i]);


}

SAFE_FREE(file_list->file);

file_list->count = 0;
file_list->capacity = 0;


}


/*

@brief  解析PE文件
@param filename PE文件路径
@param pe_info 用于存储分析结构的报告结构体指针
@return  解析结果状态码





*/


analysis_result_t parse_pe_file(const char* filename, pe_analysis_t* pe_info)
{
	//验证参数与初始化状态
	if (!parser_initalized||!filename||!pe_info)
	{

		return RESULT_ERROR_INVALID_PARAMETER;

	}
	//初始化PE信息结构体
	memset(pe_info, 0, sizeof(pe_analysis_t));

	//复制文件名
	strcpy(pe_info->filename, filename);

	//定义文件数据变量
	uint8_t* filedata = NULL;
	uint32_t filesize = 0;

	//读取文件到内存
	
	analysis_result_t result = read_file_to_memory(filename, &filedata, &filesize);

	if (result!=RESULT_SUCCESS)
	{


		return result;
	}
	//记录文件大小
	pe_info->file_size = filesize;


	//验证PE文件结构

	result=validate_pe_structure(filedata, filesize);
	if (result!=RESULT_SUCCESS)
	{

		SAFE_FREE(filedata);
		return result;
	}
	//解析DOS
	result = parse_dos_header(filedata, &pe_info->dos_header);
	if (result != RESULT_SUCCESS)
	{

		SAFE_FREE(filedata);
		return result;
	}

	//解析NT
	result = parse_nt_header(filedata, pe_info->dos_header.e_lfanew,&pe_info->nt_header);
	if (result != RESULT_SUCCESS)
	{

		SAFE_FREE(filedata);
		return result;
	}
	//提取入口点与程序基址
	pe_info->entry_point = pe_info->nt_header.OptionalHeader.AddressOfEntryPoint;
	pe_info->image_base = pe_info->nt_header.OptionalHeader.ImageBase;



	//解析节区

	result=parse_section(filedata, filesize, pe_info->dos_header.e_lfanew, &pe_info->nt_header, &pe_info->section, &pe_info->section_count);

	if (result!=RESULT_SUCCESS)
	{
		SAFE_FREE(filedata);

		return result;
	}
	//文件熵值
	pe_info->overall_entropy = calcuate_entropy(filedata, filesize);

	//释放内存
	SAFE_FREE(filedata);



	return RESULT_SUCCESS;
}


