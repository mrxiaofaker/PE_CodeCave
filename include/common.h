#ifndef COMMON_H

#define COMMON_H

//标准库函数头文件
#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>



//windows平台特定包含

#include<windows.h>
#include<winnt.h>//PE必须包含头文件
#include<stdarg.h>


//调试日志级别

#define LOG_LEVEL_DEBUG    0
//信息日志级别
#define LOG_LEVEL_INFO     1

//警告日志级别
#define LOG_LEVEL_WARNING  2

//错误日志级别
#define LOG_LEVEL_ERROR 3

//最小洞穴大小(字节)
#define MIN_CAVE_SIZE   5

//最大的洞穴大小(字节)
#define MAX_CAVE_SIZE   4096

//单文件最大洞穴数量

#define MAX_CAVES_PER_FILE   150
//单文件最大异常数量

#define MAX_ANMALIES_PER_FILE 50

//低熵值阈值 low_entropy_threshold
#define LOW_ENTROPY_THRESHOLD 4.0


//高熵值阈值
#define HIGN_ENTROPY_THRESHOLD 7.5


//零填充洞穴类型

#define CAVE_TYPE_ZERO_FILL   1


//模式填充洞穴类型pattern
#define CAVE_TYPE_PATTERN_FILL   2

//节间隙洞穴类型
#define CAVE_TYPE_SECTION_GAP   3

//覆盖层洞穴类型
#define CAVE_TYPE_OVERLAY   4

//低严重程度等级
#define ANOMALY_SEVERITY_LOW   1
//中等严重程度等级
#define ANOMALY_SEVERITY_MEDIUM   2

//高严重程度等级

#define ANOMALY_SEVERITY_HIGH   3
//关键严重程度等级critical

#define ANOMALY_SEVERITY_CRITICAL   4

//安全释放内存宏

#define SAFE_FREE(ptr) do {if(ptr){free(ptr);ptr=NULL;}} while(0)

//分析结果状态码枚举值
typedef enum {

	
	RESULT_SUCCESS = 0,
	RESULT_ERROR_FILE_NOT_FOUND = -1,
	RESULT_ERROR_INVALID_PE = -2,//无效的PE结构
	RESULT_ERROR_MEMORY_ALLOCATION = -3,
	RESULT_ERROR_INVALID_PARAMETER = -4,//无效的参数
	RESULT_ERROR_ANALYSIS_FAILED = -5//分析失败




}analysis_result_t;








#endif



