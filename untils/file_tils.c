#define  _CRT_SECURE_NO_WARNINGS
#include "file_tils.h"
#include "..\core\engine.h"


/*
@brief 检查路径
@detail 判断用户当前写入的输出路径是否存在格式错误
@param path 用户输入路径
@return TRUE 路径合法 false 路径错误


*/
BOOL is_valid_output_path(const char* path) {
	if (!path||strlen(path)==0)
	{
		return false;
	}

	if (strlen(path)>=MAX_PATH)
	{


		return false;
	}

	const char* invalid_chars = "<>:\"|? ";
	for (const char*p=path;*p;p++)
	{
		if (strchr(invalid_chars,*p))
		{
			log_message(LOG_LEVEL_ERROR, "输入路径存在错误字符");

			return false;
		}

	}


	return TRUE;

}

/*
@brief 获取文件扩展名
@param filename 文件路径
@return 文件扩展名指针不包含.


*/
const char* get_file_extension(const char* filename)
{
	if (!filename)
	{

		return false;

	}
	//d:\fakerxiao.exe ->.exe

	const char* dot = strrchr(filename, '.');

	if (!dot||dot==filename)
	{

		return "";

	}

	return dot + 1;


}
/*
@brief 检查文件是否存在
@param filename 文件路径
@return TRUE 文件存在 false 文件不存在


*/
BOOL file_exists(const char* filename)
{
	if (!filename)
	{
		return false;
	}

	FILE* file = fopen(filename, "rb");
	if (file)
	{
		fclose(file);
		return true;


	}



	return 0;
}
/*
@brief 检查文件是否为PE格式文件
@detail 通过文件扩展名判断是否为PE文件防止恶意软件抹除PE指纹
@param filename 文件路径
@return TRUE PE文件 false 非法文件


*/

BOOL is_pe_file(const char* filename)
{
	if (!filename)
	{
		return false;
	}

	const char* ext=get_file_extension(filename);
	if (!ext) {


		return false;
	}


	return (
		strcmp(ext,"exe")==0||strcmp(ext,"EXE")==0||
		strcmp(ext,"dll")==0||strcmp(ext,"DLL")==0||
		strcmp(ext,"sys")==0||strcmp(ext,"SYS")==0
		
		
		);
}

/*
@brief 获取文件大小

@param filename 文件路径

@param size  用户存储文件大小的指针
@return 操作结果的状态码



*/


analysis_result_t get_file_size(const char* filename, uint32_t* size)
{
	//验证参数有效性
	if (!filename||!size)
	{

		return RESULT_ERROR_INVALID_PARAMETER;

	}


	//打开文件
	FILE* file = fopen(filename, "rb");

	if (!file)
	{

		return RESULT_ERROR_FILE_NOT_FOUND;

	}


	//移动文件指针(末尾)
	fseek(file, 0, SEEK_END);

	//获取文件指针举例文件头部偏移(文件大小)


	long file_size = ftell(file);
	if (file_size < 0)
	{

		fclose(file);
		return RESULT_ERROR_ANALYSIS_FAILED;
	}
	*size = file_size;

	fclose(file);

	return RESULT_SUCCESS;
}
/*
@brief 将文件内容读取到内存中

@param filename 文件路径
@param data  用于存储文件数据的指针的指针
@param size  用户存储文件大小的指针
@return 操作结果的状态码



*/


analysis_result_t read_file_to_memory(const char* filename, uint8_t** data, uint32_t* size)
{
	//验证参数有效性

	if (!filename || !data || !size)
	{
		return RESULT_ERROR_INVALID_PARAMETER;

	}
	//初始化输出参数


	*data = NULL;
	*size = 0;
	//获取文件大小

	analysis_result_t result = get_file_size(filename, size);
	if (result!=RESULT_SUCCESS)
	{

		return result;

	}


	//检查是否为空文件
	if (*size==0)
	{

		return RESULT_ERROR_ANALYSIS_FAILED;

	}

	//为文件内容分配内存

	*data = malloc(*size);


	if (!*data)
	{

		return RESULT_ERROR_MEMORY_ALLOCATION;

	}

	//打开文件

	FILE* file = fopen(filename, "rb");
	if (!file)
	{
		SAFE_FREE(*data);
		return RESULT_ERROR_FILE_NOT_FOUND;


	}

	//读取文件内容

	size_t bytes_read = fread(*data, 1, *size, file);

	fclose(file);
	
	
	//检查是否完整读取了文件
	if (bytes_read!=*size)
	{//safe
		SAFE_FREE(*data);
		return RESULT_ERROR_ANALYSIS_FAILED;

	}





	

	return RESULT_SUCCESS;

}



/*
@brief 判断参数路径是为目录

@return
*/

bool is_directroy(const char* path)
{if (!path)
{
	return false;
}

	DWORD attributes= GetFileAttributesA(path);
	//判断文件是否有效,及其是不是一个目录
	return (attributes!=INVALID_FILE_ATTRIBUTES&&(attributes&FILE_ATTRIBUTE_DIRECTORY));
	



}
/*
@brief 判断文件扩展名是否匹配
@param filename 文件名
@param extensions 要匹配的文件扩展名数组
@param ext_count 扩展名数量
@return true 匹配 false 不匹配


*/


bool matches_extension(const char* filename, const char** extensions,int ext_count) {
	if (!filename||!extensions)
	{

		return RESULT_ERROR_INVALID_PARAMETER;
	}
	const char* file_ext = get_file_extension(filename);
	if (!file_ext)
	{
		return false;
	}

	for (size_t i=0;i<ext_count;i++)
	{
		if (extensions[i][0] == '*')
		{
			return TRUE;
		}
		if (_stricmp(file_ext,extensions[i])==0)
		{
			return TRUE;
		}

	}
	return false;
}

/*
@brief 将文件添加到文件列表
@param  file_list 文件列表结构体指针
@param extensions 要匹配的文件扩展名数组
@return 操作结果状态码

*/
analysis_result_t add_file_to_list(file_list_t* file_list, const char* filename) {
	//验证参数有效性
	if (!file_list||!filename)
	{


		return RESULT_ERROR_INVALID_PARAMETER;
	}

	if (file_list->count>=file_list->capacity)
	{
		uint32_t new_capacity = file_list->capacity == 0 ? 100 : file_list->capacity * 2;
		char** new_files = realloc(file_list->file, sizeof(char*) * new_capacity);

		if (!new_files)
		{
			return RESULT_ERROR_MEMORY_ALLOCATION;
		}
		file_list->file = new_files;

		file_list->capacity = new_capacity;
	
		
	}
	file_list->file[file_list->count] = malloc(strlen(filename) + 1);
	if (!file_list->file[file_list->count])
	{

		return RESULT_ERROR_MEMORY_ALLOCATION;

	}
	strcpy(file_list->file[file_list->count], filename);

	file_list->count++;



	return RESULT_SUCCESS;
}




/*
@brief 扫描目录中的指定格式文件
@param directory 要扫描的目录路径
@param extensions 要匹配的文件扩展名数组
@param ext_count 扩展名数量
@param recursive 是否递归扫描子目录
@param file_list 用于存储找到的文件
@return 操作结果状态码


*/

analysis_result_t scan_directory_for_files(const char* directory, const char** extensions, int ext_count, bool recursive, file_list_t* file_list) {
	//验证参数有效性
	if (!directory||!file_list)
	{
		return RESULT_ERROR_INVALID_PARAMETER;


	}
	WIN32_FIND_DATAA find_data = { 0 };
	HANDLE find_handle = 0;
	char serch_path[MAX_PATH] = { 0 };
	snprintf(serch_path, sizeof(serch_path), "%s\\*", directory);
	
	find_handle = FindFirstFileA(serch_path, &find_data);

	if (find_handle==INVALID_HANDLE_VALUE)
	{
		return RESULT_ERROR_FILE_NOT_FOUND;


	}


	do 
	{

		//过滤当前目录与上一级目录
		if (strcmp(find_data.cFileName,".")==0||strcmp(find_data.cFileName,"..")==0)
		{


			continue;


		}

		char full_path[MAX_PATH] = { 0 };

		snprintf(full_path, sizeof(full_path), "%s\\%s", directory, find_data.cFileName);
		if (find_data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)
		{
			if (recursive)
			{

				scan_directory_for_files(full_path, extensions, ext_count, recursive, file_list);
			}

		}
		else
		{

			if (matches_extension(find_data.cFileName,extensions,ext_count))
			{

				analysis_result_t add_result = add_file_to_list(file_list, full_path);
				if (add_result != RESULT_SUCCESS)
				{
					FindClose(find_handle);
					return add_result;
				}
			}


		}




	} while (FindNextFileA(find_handle,&find_data));

	FindClose(find_handle);
	return RESULT_SUCCESS;
}
