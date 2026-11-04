#ifndef TYPE_H
#define TYPE_H

#include"common.h"

typedef struct  
{
//是否输出详细信息
	bool verbose_output;

//是否生成JSON格式报告
	bool generation_json_report;

//是否生成HTML报告

    bool generation_html_report;
//报告输出目录路径
	char output_directory[MAX_PATH];

//日志输出级别
	uint8_t log_level;

//熵值异常检测阀值
	double entropy_threshold;

//最小的代码洞穴尺寸

	uint32_t min_cave_size;
//最大的代码洞穴尺寸
	uint32_t max_cave_size;


}config_t;



typedef  struct  
{//节名称
	char name[IMAGE_SIZEOF_SHORT_NAME + 1];
	//虚拟地址
	uint32_t virtual_address;
	//虚拟大小

	uint32_t virtual_size;
	//文件偏移
	uint32_t raw_address;

	//文件大小
	uint32_t raw_size;

	//节的属性
	uint32_t characteristics;

		//信息熵值

		double entropy;


	//是否执行
		bool is_executable;

	//是否写入
		bool is_writable;





}section_info_t;



//熵值8.0是完全随机,0.0完全有序的是00啥的,1.0~3.0低熵值常见的代码段,有部分重复的数据
//7.0~8.0可能是加密与压缩的数据

typedef struct 
{
	//洞穴在文件中的偏移
	uint32_t offset;
	uint32_t rva;

	//洞穴大小
	uint32_t size;

	//所属PE节的索引

	uint32_t section_index;
	//洞穴类型
	uint32_t cave_type;

	//可疑程度评分
	double suspicion_level;


	//洞穴描述信息


	char descriptor[256];



}code_cave_t;

typedef struct  
{
	//异常模式唯一标识符
	uint32_t pattern_id;

	//异常模式名称
	char pattern_name[64];

	//严重程度等级
	uint32_t severity;


	//异常模式描述

	char descriptor[256];

    //异常文件偏移量
	uint32_t detected_offset;

	//异常的PE节索引
	uint32_t section_index;



}anomaly_pattern_t;


typedef struct  
{
	//文件路径


	char filename[MAX_PATH];
	//文件大小
	uint32_t file_size;

	//Dos
	IMAGE_DOS_HEADER dos_header;

	//Nt

	IMAGE_NT_HEADERS nt_header;

	//SECTION
	section_info_t* section;
	//SECTION_count
	uint16_t section_count;


	//OEP
	uint32_t entry_point;


	//IMAGEBASE

	uint64_t image_base;

	//文件熵值
	double overall_entropy;





}pe_analysis_t;


typedef struct _analysis_report_t {
	//目标文件路径
	char target_file[MAX_PATH];

	//分析开始时间
	
	time_t analysis_time;


	//发现的代码洞穴总数
	uint32_t total_cave_found;

	//高风险的代码洞穴数量
	uint32_t hign_risk_cave;

	//检测的异常模式数量
	uint32_t anomalies_detected;

	//整体风险评估
	double overall_risk_score;

	//代码洞穴详细信息数组(洞穴检测器负责查找)
	code_cave_t cave[MAX_CAVES_PER_FILE];

	//异常模式详细信息数组(异常检测器负责评估)
	anomaly_pattern_t anomalies[MAX_ANMALIES_PER_FILE];

	//PE 文件结构分析结果

	pe_analysis_t pe_info;






}analysis_report_t;

typedef struct 
{
	//要扫描的目录路径

	char directory[MAX_PATH];
	//要匹配的文件扩展名数组
	const char** extensions;

	//扩展名数量
	int extension_count;
	//是否递归扫描子目录
	bool recursive_scan;

	//是否为每个文件生成单独报告
	bool generate_individual_report;

	//是否生成批量分析汇总报告
	bool generate_summary_report;

	//汇总报告文件名
	char summary_filename[MAX_PATH];



}batch_config_t;

typedef struct  
{
	//文件路径数组
	char** file;
	//当前文件数量
	uint32_t count;
	//数组容量
	uint32_t capacity;



}file_list_t;


typedef struct  
{
	//计划分析的文件总数
	uint32_t total_files;
	//已经处理的文件数量
	uint32_t processed_files;
    //成功分析的文件数量
	uint32_t successfuk_analyses;
	//分析失败的文件数量
	uint32_t failed_analyses;
	//发现的代码洞穴总数
	uint32_t total_caves_found;
	//发现的异常模式总数
	uint32_t total_anomalies_found;
	//高风险的文件数量
	uint32_t hign_risk_files;
	//平均风险评分
	uint32_t average_risk_score;
	//批量分析开始时间
	time_t start_time;
	//批量分析结束时间
	time_t end_time;

}batch_statistic_t;



#endif

