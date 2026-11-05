#include "report_generator.h"
#include "../core/engine.h"

const char* get_cave_type_string(uint8_t type) {

	switch (type)
	{
	case 1:
		return "CAVE_TYPE_ZERO_FILL";
	case 2:
		return "CAVE_TYPE_PATTERN_FILL";
			
	case 3:
		return "CAVE_TYPE_SECTION_GAP";
	case 4:
		return "CAVE_TYPE_OVERLAY";

	default:
		return "UNKNOW";
		break;
	}

}




/*
@brief  打印分析报告摘要内容
@ param report 分析报告结构体指针
*/


void print_report_summary(const analysis_report_t* report) {
	printf("\r\n");
	log_message(LOG_LEVEL_INFO, "目标文件 %s", report->target_file);
	log_message(LOG_LEVEL_INFO, "文件大小 %d",report->pe_info.file_size );
	log_message(LOG_LEVEL_INFO, "洞穴数量 %d",report->total_cave_found );
	log_message(LOG_LEVEL_INFO, "异常数量 %d",report->anomalies_detected );
											 



}

/*
@brief  打印pe结构信息
@ param report 分析报告结构体指针
*/
void print_pe_struct_info(const analysis_report_t* report) {

	printf("\r\n");

	log_message(LOG_LEVEL_INFO, "PE结构信息");
	log_message(LOG_LEVEL_INFO, "入口点 0x%08x",report->pe_info.entry_point);
	log_message(LOG_LEVEL_INFO, "映射基址 0x%llx",(unsigned long long)report->pe_info.image_base);
	log_message(LOG_LEVEL_INFO, "节区数量 0x%08x",report->pe_info.section_count);
	log_message(LOG_LEVEL_INFO, "文件熵值 0x%08x",report->pe_info.overall_entropy);
	
	if (report->pe_info.section)
	{
		for (size_t i=0;i<report->pe_info.section_count;i++)
		{

			const section_info_t* section = &report->pe_info.section[i];

			log_message(LOG_LEVEL_INFO, "%-8s VA-0x%08X  VSize==0x%08X RA=0x%08X RSize=0x%08x Entropy=%.3f %s%s",
				section->name,
				section->virtual_address,
				section->virtual_size,
				section->raw_address,
				section->raw_size,
				section->entropy,
				section->is_executable ? "X" : "-",
				section->is_writable? "W":"-"
			);

		}


	}




}
/*

@brief  打印代码洞穴的详细信息
@param caves  代码洞穴的数组指针
@param cave_count 代码洞穴数量
@param verbose 是否输出详细信息
@return  分析结果状态码





*/

void print_caves_info(const code_cave_t* caves,uint32_t cave_count,bool verbose) {
	for (size_t i=0;i<cave_count;i++)
	{
		const code_cave_t* cave = &caves[i];
		log_message(LOG_LEVEL_INFO, "CAVE #%04d:  OFFSET=0x%08X SIZE=%04d TYPE=%s",
			i + 1,
			cave->offset,
			cave->size,
			get_cave_type_string(cave->cave_type));

		if (verbose)
		{
			log_message(LOG_LEVEL_INFO, "DESCRIPTOR=%s", cave->descriptor);

		}
		printf("\r\n");
	}
	


}
/*

@brief  打印异常模式的详细信息
@param anomalies 异常模式数组指针
@param anomaly_count 异常模式数量
@param verbose 是否输出详细信息
@return  分析结果状态码





*/

void print_anomaly_pattern_info(const anomaly_pattern_t*anomalies,uint32_t anomaly_count,BOOL verbose) {
	for (size_t i = 0; i < anomaly_count; i++)
	{
		const anomaly_pattern_t* anomaly = &anomalies[i];
		log_message(LOG_LEVEL_INFO, "ANOMALT #%04d:  OFFSET=0x%08X NAME=%s ",
			i + 1,
			anomaly->detected_offset,
			anomaly->pattern_name
			);
		if (verbose)
		{
			log_message(LOG_LEVEL_INFO, "DESCRIPTOR=%s", anomaly->descriptor);

		}
		printf("\r\n");
	}
	


}



/*

@brief  生成控制台格式的分析报告
@param report 分析报告结构体指针
@param verbose 是否输出详细信息
@return  分析结果状态码





*/
analysis_result_t generate_console_report(const analysis_report_t* report, bool verbose)
{
	
	//参数验证
	if (!report)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	//输出信息
	printf("/r/n");
	log_message(LOG_LEVEL_INFO, "==========================================================================");
	log_message(LOG_LEVEL_INFO, "=====================代码洞穴检测分析=====================================");
	log_message(LOG_LEVEL_INFO, "==========================================================================");
	//报告摘要
	print_report_summary(report);
	//详细信息
	if (verbose)
	{
		print_pe_struct_info(report);
	}

	//洞穴信息
	if (report->total_cave_found>0)
	{


		print_caves_info(report->cave,report->total_cave_found,verbose);
	}



	//异常信息
	if (report->anomalies_detected>0)
	{

		print_anomaly_pattern_info(report->anomalies, report->anomalies_detected, verbose);

	}

	





	return RESULT_SUCCESS;


}
