#define _CRT_SECURE_NO_WARNINGS
#include "anomaly_detector.h"

static bool anomaly_detector_initialize = false;
static uint32_t next_anomaly_id = 1; //用于生成唯一的异常模式ID
/*
@brief 初始化异常检测器

@return 初始化结果状态码


*/


analysis_result_t initialize_anmoaly_detector(VOID)
{
	if (anomaly_detector_initialize)
	{
		return RESULT_SUCCESS;
	}
	anomaly_detector_initialize = true;

	return RESULT_SUCCESS;
}
/*
@brief 清理异常检测器资源




*/

VOID cleanup_anmoaly_detector(VOID)
{
	anomaly_detector_initialize = false;
}


/*

@brief  根据模式名称和置信度计算异常严重性等级
@param pattern_name 异常模式名称
@param confidence 异常模式置信度
@return  异常严重性等级
*/

uint8_t get_anomaly_severity(const char* pattern_name, double confidence)
{   
	if (strstr(pattern_name,"entropy"))
	{
		if (confidence<1.0)
		{
			//极低阀值< 1.0

			return ANOMALY_SEVERITY_HIGH;

		}
		else if (confidence < 3.0) {
			//1.0<低阀值< 3.0

			return ANOMALY_SEVERITY_MEDIUM;
		}
		else if (confidence>7.5)
		{
			//高阀值> 7.5
			return ANOMALY_SEVERITY_HIGH;

		}
		else {
			//中等阀值 3.0~7.5
			return ANOMALY_SEVERITY_LOW;
			
		}

	}



	return ANOMALY_SEVERITY_MEDIUM;
}

/*

@brief  根据相邻节区熵值变量异常
@param   entropy1 第一个熵值
@param   entropy2 第二个熵值
@return  true 熵值变化异常 false 熵值变化正常
*/
bool is_anomaly_entropy_change(double entropy1, double entropy2)
{
	double diff=(entropy1>entropy2)?(entropy1-entropy2):(entropy2-entropy1);


	return diff>4.0;
}


/*

@brief  检测代码洞穴聚类异常模式
@param pe_info  PE文件分析信息结构体指针
@param caves 代码洞穴指针
@param cave_count 代码洞穴数量
@param anomalied 输出异常数组
@param anomaly_count 输出异常数量
@param max_anomalies 最大异常模式数量限制
@return  解析结果状态码





*/
analysis_result_t detect_entry_point_cave_cluster_anomalies(const pe_analysis_t* pe_info, const code_cave_t* caves, uint32_t cave_count, anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies) {
	//参数验证
	if (!pe_info || !anomalied ) {
		return RESULT_ERROR_INVALID_PARAMETER;
	}
	//初始化输出参数
	*anomaly_count = 0;

	//代码洞穴验证
	if (!caves||cave_count==0)
	{
		return RESULT_SUCCESS;
	}

	//记录程序入口
	uint32_t entry_point_rva = pe_info->entry_point;

	//遍历代码洞穴
	for (uint32_t i=0;i<cave_count&&*anomaly_count<max_anomalies;i++)
	{
		//FOA  ->RVA
		//RVA=文件偏移-文件基址+内存基址
		uint32_t cave_rva = caves[i].rva;


		//计算洞穴与代码入口点的绝对距离

		uint32_t distance = (cave_rva > entry_point_rva) ? (cave_rva - entry_point_rva) : (entry_point_rva - cave_rva);
		//阈值设定256  短跳

		if (distance<256)
		{
			//异常模式信息提取
			anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];
			//填充异常模式信息
			anomaly->section_index = caves[i].section_index;
			anomaly->detected_offset = caves[i].offset;
			anomaly->pattern_id = next_anomaly_id++;
			anomaly->severity = ANOMALY_SEVERITY_HIGH;


			strcpy(anomaly->pattern_name, "入口点附近洞穴");
			snprintf(anomaly->descriptor,
				sizeof(anomaly->descriptor),
				"在入口点 %d 字节处发现代码洞穴"
				, distance);

			(*anomaly_count)++;



		}


	}

	return RESULT_SUCCESS;


}
/*

@brief  检测代码洞穴聚类异常模式
@param caves 代码洞穴指针
@param cave_count 代码洞穴数量
@param anomalied 输出异常数组
@param anomaly_count 输出异常数量
@param max_anomalies 最大异常模式数量限制
@return  解析结果状态码





*/
analysis_result_t detect_cave_cluster_anomalies(const code_cave_t* caves, uint32_t cave_count, anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies)
{
	//参数校验
	if (!caves || !anomalied || !anomaly_count) {

		return RESULT_ERROR_INVALID_PARAMETER;

	}

	//初始化输出参数
	*anomaly_count = 0;

	//洞穴数量检测
	if (cave_count<2)
	{
		return RESULT_SUCCESS;
	}
	//聚类分析算法
	uint32_t clusters[MAX_CAVES_PER_FILE] = { 0 }; //存储每个聚集的洞穴大小
	uint32_t cluster_count = 0;                    //聚集总数
	const uint32_t cluster_shreshold = 1024;       //聚类距离阈值

	//算法思路 如果两个洞穴的偏移量差小于阈值且在同一节中,则认为它们属于同一个聚类


	for (uint32_t i = 0; i < cave_count; i++)
	{
		
		for (size_t j=i+1;j<cave_count;j++)
	{
			//计算两个洞穴的绝对距离
			uint32_t distance = (caves[j].offset > caves[i].offset) ? (caves[j].offset - caves[i].offset) : (caves[i].offset - caves[j].offset);
			//条件1 距离小于阈值
			// 条件2 洞穴在同一节中

			if (distance<cluster_shreshold&&caves[i].section_index==caves[j].section_index)
			{  //增加当前聚类的洞穴数量
				clusters[cluster_count]++;

			}




	}
		//当前聚类有洞穴,移动到下一个聚类
		if (clusters[cluster_count]>0)
		{
			cluster_count++;

		}




	}
	//聚类异常判断
	if (cluster_count>3&&*anomaly_count<max_anomalies)
	{

		
		//异常模式信息提取
		anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];
		//填充异常模式信息
		anomaly->section_index = caves[0].section_index;
		anomaly->detected_offset = caves[0].offset;
		anomaly->pattern_id = next_anomaly_id++;
		anomaly->severity = ANOMALY_SEVERITY_HIGH;


		strcpy(anomaly->pattern_name, "洞穴聚集");
		snprintf(anomaly->descriptor,
			sizeof(anomaly->descriptor),
			"检测到 %d 个代码洞穴的可疑聚集"
			,cluster_count);

		(*anomaly_count)++;


	}



	return RESULT_SUCCESS;




}
/*

@brief  熵值异常检测算法
@param pe_info  PE文件分析信息结构体指针
@param anomalied  输出异常数组
@param anomaly_count 输出异常数量
@param max_anomalies  最大异常模式数量限制
@return  解析结果状态码





*/
analysis_result_t detect_entropy_anomalies(const pe_analysis_t* pe_info, 
	anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies)
{
	//参数校验
	if (!pe_info||!anomalied)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}
	//初始化输出参数
	*anomaly_count = 0;

	//单节熵值异常检测
	for (uint32_t i=0;i<pe_info->section_count&&*anomaly_count<max_anomalies;i++)
	{

		//获取当前节信息
		const section_info_t* section = &pe_info->section[i];


		//代码节
		if (section->is_executable&&section->entropy< LOW_ENTROPY_THRESHOLD)
		{
			//异常模式信息提取
			anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];
			//填充异常模式信息
			anomaly->section_index = i;
			anomaly->detected_offset = section->raw_address;
			anomaly->pattern_id = next_anomaly_id++;
			anomaly->severity = get_anomaly_severity("entropy", section->entropy);


			strcpy(anomaly->pattern_name, "代码异常节:低熵值可执行节");
			snprintf(anomaly->descriptor,
				sizeof(anomaly->descriptor), 
				"可执行节名称: %s,可疑熵值: %.2f"
				"正常可执行代码熵值应该在4.0~7.0之间,低于4.0可能是异常填充数据"
				"可能原因是 process hollowing code cave 或恶意替换"
				, section->name, section->entropy);

			(*anomaly_count)++;
		}
		//数据节

		if (section->is_executable&&section->entropy>HIGN_ENTROPY_THRESHOLD){
			//检测是否溢出
			if (*anomaly_count>max_anomalies)break;

			//异常模式信息提取
			anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];
			//填充异常模式信息
			anomaly->section_index = i;
			anomaly->detected_offset = section->raw_address;
			anomaly->pattern_id = next_anomaly_id++;
			anomaly->severity = get_anomaly_severity("entropy", section->entropy);


			strcpy(anomaly->pattern_name, "代码异常节:高熵值可执行节");
			snprintf(anomaly->descriptor,
				sizeof(anomaly->descriptor),
				"数据节名称: %s,可疑高熵值: %.2f"
				"正常可执行代码熵值应该在4.0~7.0之间,低于4.0可能是异常填充数据"
				"可能原因是 加密数据 压缩数据 隐藏的恶意代码"
				, section->name, section->entropy);

			(*anomaly_count)++;


		}




	}

	//相邻节熵值变化检测
	for (uint32_t i=0;i+1<pe_info->section_count&&*anomaly_count<max_anomalies;i++)
	{
		//当前节
		const section_info_t* current = &pe_info->section[i];

		//下一个节
		const section_info_t* next = &pe_info->section[i + 1];

		//
		if (is_anomaly_entropy_change(current->entropy, next->entropy))
		{
			//获取当前节信息
			const section_info_t* section = &pe_info->section[i];




			//异常模式信息提取
			anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];
			//填充异常模式信息
			anomaly->section_index = i + 1;
			anomaly->detected_offset = next->raw_address;
			anomaly->pattern_id = next_anomaly_id++;
			anomaly->severity = ANOMALY_SEVERITY_MEDIUM;
			double entropy_diff = (current->entropy > next->entropy)
				? (current->entropy - next->entropy)
				: (next->entropy - current->entropy);

			strcpy(anomaly->pattern_name, "熵值不连续");
			snprintf(anomaly->descriptor,
				sizeof(anomaly->descriptor),
				"节 %s 与节 %s 之间的熵值变化异常: %.2f -> %.2f"
				"熵值变化幅度 %.2f"
				"可能原因是节区被代码注入,数据篡改 恶意拼接,或者存在隐藏的加密/压缩数据",
				current->name, next->name, current->entropy, next->entropy, entropy_diff

			);

			(*anomaly_count)++;




		}
	}




	return RESULT_SUCCESS;
}
/*

@brief  检查PE文件节结构相关的异常模式,
@param pe_info  PE文件分析信息结构体指针
@param anomalied  输出异常数组
@param anomaly_count 输出异常数量
@param max_anomalies  最大异常模式数量限制
@return  解析结果状态码





*/
analysis_result_t detect_section_anomalies(const pe_analysis_t* pe_info, 
	anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies)
{
	//参数校验
	if (!pe_info||!anomalied)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}
	//初始化输出参数
	*anomaly_count = 0;


	//遍历节区结构
	for (uint32_t i=0;i<pe_info->section_count&&*anomaly_count<max_anomalies;i++)
	{
		//获取当前节信息
		const section_info_t* section = &pe_info->section[i];

		//可疑权限组合(不能同时可写可执行)
		if (section->is_executable&&section->is_writable)
		{
			//异常模式信息提取
			anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];

			//填充异常模式信息
			anomaly->section_index = i;
			anomaly->detected_offset = section->raw_address;
			anomaly->pattern_id = next_anomaly_id++;
			anomaly->severity = ANOMALY_SEVERITY_HIGH;


			strcpy(anomaly->pattern_name, "可疑节标记:可写可`执行");
			snprintf(anomaly->descriptor,
				sizeof(anomaly->descriptor),
				"节名称: %s,具有可写可执行权限"
				
				, section->name);

			(*anomaly_count)++;
		}

		//纯虚拟节(内存中占据内存,但是文件中不占任何空间/BSS节)

		if (section->virtual_size>0&&section->raw_size==0)
		{
			//检测是否溢出
			if (*anomaly_count > max_anomalies)break;
			//异常模式信息提取
			anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];
			//填充异常模式信息
			anomaly->section_index = i;
			anomaly->detected_offset = section->raw_address;
			anomaly->pattern_id = next_anomaly_id++;
			anomaly->severity = ANOMALY_SEVERITY_MEDIUM;


			strcpy(anomaly->pattern_name, "纯虚拟节");
			snprintf(anomaly->descriptor,
				sizeof(anomaly->descriptor),
				"节名称: %s,仅存在虚拟内存中(虚拟大小: %d,文件大小:0)"

				, section->name,section->virtual_size);

			(*anomaly_count)++;
			
		}


		//异常大小比例)(虚拟大小比例与文件大小比例差距过大了)(>10.0  <0.1)
		if (section->raw_size>0&&section->virtual_size>0)
		{
			double size_ratio = (double)section->virtual_size / (double)section->raw_size;
			if (size_ratio>10.0||size_ratio<0.1)
			{

				//检测是否溢出
				if (*anomaly_count > max_anomalies)break;
				//异常模式信息提取
				anomaly_pattern_t* anomaly = &anomalied[*anomaly_count];
				//填充异常模式信息
				anomaly->section_index = i;
				anomaly->detected_offset = section->raw_address;
				anomaly->pattern_id = next_anomaly_id++;
				anomaly->severity = ANOMALY_SEVERITY_MEDIUM;


				strcpy(anomaly->pattern_name, "异常大小比例");
				snprintf(anomaly->descriptor,
					sizeof(anomaly->descriptor),
					"节名称: %s,异常的虚拟/原始大小比例(%.2f)"

					, section->name, size_ratio);

				(*anomaly_count)++;
			}
		}



	}



	return RESULT_SUCCESS;
}

/*

@brief  检测所有类型的异常模式
@param pe_info  PE文件分析信息结构体指针
@param caves  代码洞穴数组指针
@param cave_count  代码洞穴数量
@param anomalied  存储检测到的异常模式数组
@param anomaly_count 存储检测到的异常模式数量的指针
@param max_anomalies  最大异常模式数量限制
@return  解析结果状态码





*/

analysis_result_t detect_anomalies(const pe_analysis_t* pe_info,
	const code_cave_t* caves,
	uint32_t cave_count, anomaly_pattern_t* anomalied,
	uint32_t* anomaly_count, uint32_t max_anomalies)
{
	//参数有效性检测
	if (!pe_info||!anomalied||!anomaly_count)
	{

		return RESULT_ERROR_INVALID_PARAMETER;


	}

	//初始化输出参数
	*anomaly_count = 0;


	//初始化流程变量
	analysis_result_t result = RESULT_SUCCESS;
	uint32_t temp_count = 0;

	//检测阶段-熵值异常分析(加密数据 压缩数据 异常填充)

	result = detect_entropy_anomalies(pe_info, &anomalied[*anomaly_count],
		&temp_count, max_anomalies-*anomaly_count);

	if (result == RESULT_SUCCESS)
	{
		*anomaly_count += temp_count;
	}
	
	
	if (*anomaly_count>=max_anomalies)
	{


		return RESULT_SUCCESS;
	}

	//检测阶段- 结构异常分析(权限组合 大小比例 虚拟节)
	temp_count = 0;
	result = detect_section_anomalies(pe_info, &anomalied[*anomaly_count],
		&temp_count, max_anomalies - *anomaly_count);

	if (result == RESULT_SUCCESS)
	{
		*anomaly_count += temp_count;
	}

	
	if (*anomaly_count >= max_anomalies)
	{


		return RESULT_SUCCESS;
	}
	//检测阶段-代码洞穴聚集分析(攻击者可以利用聚集的代码洞穴进行分散的恶意代码注入)
	temp_count = 0;
	result = detect_cave_cluster_anomalies(caves, cave_count, &anomalied[*anomaly_count],
		&temp_count, max_anomalies - *anomaly_count);

	if (result == RESULT_SUCCESS)
	{
		*anomaly_count += temp_count;
	}


	if (*anomaly_count >= max_anomalies)
	{


		return RESULT_SUCCESS;
	}

	//检测阶段-可疑入口点(检测入口点附加是否存在代码洞穴)
	temp_count = 0;
	result = detect_entry_point_cave_cluster_anomalies(pe_info, caves, cave_count, &anomalied[*anomaly_count],
		&temp_count, max_anomalies - *anomaly_count);

	if (result == RESULT_SUCCESS)
	{
		*anomaly_count += temp_count;
	}


	

	return RESULT_SUCCESS;
}
