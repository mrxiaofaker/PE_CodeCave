#define _CRT_SECURE_NO_WARNINGS
#include "engine.h"
#include "..\\parser\pe_parser.h"
#include "..\\detector\anomaly_detector.h"
#include "..\\analyzer\cave_detector.h"
#include "..\\untils\\file_tils.h"

static config_t* g_config = NULL;
static bool g_engine_initialized = false;
static uint8_t current_log_level = LOG_LEVEL_INFO;
/*

@brief  输出日志消息
@param level 日志级别
@param format 格式化字符串
@param ...  可变动参数列表





*/



void log_message(uint8_t level, const char* format, ...)
{
	//输出日志级别是否满足输出条件

	if (level < current_log_level)
	{


		return;
	}
	//日志级别名称数组
	const char* level_names[] = { "调试","信息","警告","错误" };


	//获取当前时间搓
	time_t now = time(NULL);

	//转换为本地时间结构

	struct  tm* tm_info = localtime(&now);

	//输出时间搓及日志级别
	printf("[%2d:%02d:%02d]  [%s]",
		tm_info->tm_hour,
		tm_info->tm_min,
		tm_info->tm_sec,
		level_names[level]);

	//初始化可变参数列表
	va_list args;

	va_start(args, format);

	vprintf(format,args);

	va_end(args);


	printf("\n");


	return;

}

/*

@brief  设置日志输出等级
@param level 日志级别(DEBUG=0 INFO=1 WARNING =2 ERROR=3)





*/
void Set_log_level(uint8_t level)
{
	current_log_level = level;


}

/*
@brief 初始化分析引擎
@param config 用户配置结构体指针
@return 初始化结果状态码






*/



analysis_result_t initialize_engine(config_t* config)
{
	//检查引擎是否初始化
	if (g_engine_initialized)
	{

		log_message(LOG_LEVEL_WARNING, "引擎已经初始化完成");
		return RESULT_SUCCESS;

	}

	//验证参数配置
	if (!config)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	//全局配置分配内存
	g_config = malloc(sizeof(config_t));
	if (!g_config)
	{

		return RESULT_ERROR_MEMORY_ALLOCATION;
	}

	//复制配置到全局
	memcpy(g_config, config, sizeof(config_t));

	//初始化PE解析器
	if (initialize_pe_parser()!=RESULT_SUCCESS)
	{
		SAFE_FREE(g_config);

		return RESULT_ERROR_ANALYSIS_FAILED;

	}


	//初始化代码洞穴检测器
	if (initialize_cave_dectector() != RESULT_SUCCESS)
	{

		clean_pe_parser();
		SAFE_FREE(g_config);

		return RESULT_ERROR_ANALYSIS_FAILED;

	}

	//初始化异常模式检测器
	if (initialize_anmoaly_detector() != RESULT_SUCCESS)
	{

		clean_pe_parser();
		cleanup_cave_detector();
		SAFE_FREE(g_config);

		return RESULT_ERROR_ANALYSIS_FAILED;

	}

	//设置初始化标志

	g_engine_initialized = true;
	log_message(LOG_LEVEL_INFO, "代码洞穴检测引擎初始化成功");







	return RESULT_SUCCESS;
}
/*
@brief 清理分析引擎





*/
void cleanup_engine(void)
{
//检查是否已经初始化
	if (!g_engine_initialized)
	{
		return;

	}


	//清理PE解析器
	clean_pe_parser();


	//清理代码洞穴检测器
	cleanup_cave_detector();


	//清理异常模式检测器

	cleanup_anmoaly_detector();

	//释放全局配置内存
	SAFE_FREE(g_config);

	//重置初始化标志

	g_engine_initialized = false;

	log_message(LOG_LEVEL_INFO, "代码洞穴检测引擎清理完成");





}
/*

@brief  分析单个文件
@param filename 分析的文件路径
@param report 用于存储分析结构的报告结构体指针
@return  分析结果状态码





*/

analysis_result_t analyze_file(const char* filename, analysis_report_t* report)
{
	//检查引擎是否初始化

	if (!g_engine_initialized)
	{
		return RESULT_ERROR_ANALYSIS_FAILED;

	}

	//验证参数有效性
	if (!filename||!report)
	{

		return RESULT_ERROR_INVALID_PARAMETER;//无效的参数
	}

	//检查文件是否存在
	if (!file_exists(filename))
	{

		return RESULT_ERROR_FILE_NOT_FOUND;

	}


	//初始化报告结构体

	memset(report, 0, sizeof(analysis_report_t));

	//记录目标文件路径

	strcpy(report->target_file, filename);

	//记录分析时间
	report->analysis_time = time(NULL);

	//用户信息提示
	log_message(LOG_LEVEL_INFO, "开始分析文件:%s", filename);

	//解析PE文件结构
	analysis_result_t result = parse_pe_file(filename, &report->pe_info);
	if (result!=RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_ERROR, "PE文件解析失败");

		return result;
	}
	//检测代码洞穴(数量限制150)
	result = detect_code_caves(&report->pe_info, report->cave,
		&report->total_cave_found, MAX_CAVES_PER_FILE);
	if (result != RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_ERROR, "代码洞穴检测失败");

		return result;
	}

	//检测异常模式(数量限制50)

	result = detect_anomalies(&report->pe_info, report->cave,
		report->total_cave_found,
		report->anomalies,&report->anomalies_detected,
		MAX_ANMALIES_PER_FILE);

	if (result != RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_ERROR, "异常模式检测失败");

		return result;
	}

	return RESULT_SUCCESS;

	
}
