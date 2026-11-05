/*

CodeCave
	|- readme.md               项目说明文档
	|- main.c                  程序入口文件
	|- PE_CodeCave.vcxproj     工程项目文件
	|
	|- include/                公共头文件目录
	|   |- common.h            通用宏定义 常量
	|   |- types.h             数据结构定义
	|
	|- core/                   核心引擎模块
	|   |- engine.c            引擎接口声明
	|   |- engine.h            引擎实现
	|
	|- parser/                  PE文件解析模块
	|     |-pe_parser.h         PE解析器接口
	|     |-pe_parser.c         PE解析器实现
	|
	|- analyzer/                洞穴检测模块
	|     |-cave_detector.h     洞穴检测器接口
	|     |-cave_detector.c     洞穴检测算法
	|
	|
	|-detector/                 异常检测模块
	|  |- anomaly_detector.h    异常模型
	|
	|- reporter/                报告生成模块
	|  |-report_generator.h     报告生成器接口
	|  |-report_generator.c     多格式报告输出
	|
	|
	|- untils/                    工具函数模块
	|   |-file_tils.h            文件工具接口
	|   |-file_tils.c            文件操作目录扫描
	|
	|


	用户交互层  -main.c         # 菜单系统 用户输入输出处理



	控制协调层  -engine.c       #流程控制 模型协调
	            -初始化管理:系统启动与资源分配
				-流程控制:分析任务调度与执行
				-模块协调:各个子模块间的通信与数据传递
				-错误处理:统一的错误异常处理与恢复机制



	业务逻辑层  -pe_parser.c          #PE解析模块
				-cave_detect.c          #检测分析模块
				_anomaly_detector.c   #检测分析模块


	服务管理层  -report_generator.c   #输出模块
	            -file_tils.c          #工具模块


    代码规范
	    -一致性原则(命名风格)
		-防御性编程(参数验证/内存管理/边界检查)
        -文档规范

		//@brief 两数之和

		//@details 该函数使用了xxxxxxxxxxxx完成

		//@param[in]

		//@param[out]

        //@param[optional]

		//@return 检查结果

		//@retavl   RESULT_SUCCESS
		//@retavl   RESULT_ERROR_INVALID_PARAM
		//@retavl   RESULT_ERROR_MEMORY_ALLOCALTION
	

	    //@note 调用者必须确保xxxxxxxxxxxxx
		//@warning 参数1必须使用非分页内存否则xxxxxxxxxx



		int Add(int a,int b);





*/
#define _CRT_SECURE_NO_WARNINGS

#include"./include/common.h"
#include "./core/engine.h"
#include "./untils/file_tils.h"
#include "./reporter/report_generator.h"
#include "./parser/pe_parser.h"
#include "./cli.h"


/*
@brief 打印采用程序启动横幅
@details 显示程序标题
*/
VOID print_banner(void) {

	printf("\n");
	printf("======================================================\r\n");




	printf("===================洞穴检测系统=======================\r\n");
	printf("===================防御性安全分析工具=================\r\n");



	printf("======================================================");
	printf("\n");



}
/*
@brief 打印主菜单选项
@details 显示程序的主要功能选项供给用户选择

*/

VOID print_menu(void) {
	printf("\n---- 主菜单 ----");
	printf("\n1.分析PE 文件\r\n");
	printf("2.批量分析多个文件\r\n");
	printf("3.配置设置\r\n");
	printf("4.显示帮助\r\n");
	printf("5.退出\r\n");
	printf("\n请选择选项(1-5):");






}
/*
@brief 打印帮助信息
@details 显示程序的功能说明,检测原理,风险等级定义等

*/
VOID print_help(VOID) {






}
/*
@brief 获取用户确认
@detail 显示确认消息并等待用户输入 y/n 进行确定执行
@param message 显示给用户确认的消息
@return TRUE 用户确认 false 用户拒绝


*/


BOOL get_user_confiemation(const char* message) {

	char input[10] = { 0 };
	printf("%s (y/n)", message);

	if (fgets(input,sizeof(input),stdin))
	{

		return (input[0] == 'y' || input[0] == 'Y');

	}

	return false;
}
/*
@brief 打印配置菜单
@detail 显示当前配置状态与可修改配置选项
@param message 配置结构体指针


*/
void print_config_menu(config_t* config) {

	printf("\n---- 配置设置 ----\n");
	printf("1. 详细输出: %s\r\n", config->verbose_output ? "已启用" : "已禁用");
	printf("2. JSON 报告: %s\r\n", config->generation_json_report ? "已启用" : "已禁用");
	printf("3. HTML 报告: %s\r\n", config->generation_html_report ? "已启用" : "已禁用");
	printf("4. 输出目录: %s\r\n", config->output_directory);
	printf("5. 熵值阈值: %.2f\r\n", config->entropy_threshold);
	printf("6. 最小洞穴大小: %u\r\n", config->min_cave_size);
	printf("7. 日志级别: %u\r\n", config->log_level);
	printf("8. 返回主菜单\r\n");
	printf("\n请输入选项(1-8): ");


}



/*
@brief 配置程序设置
@detail 提供交互式界面让用户可以修改根系参数与输出选项
@param message 配置结构体指针


*/
void configure_settings(config_t* config) {
	//定义选择变量
	int choice = 0;


	//定义输入缓冲区
	char input[MAX_PATH] = { 0 };


	//进入配置循环
	while (1)
	{
		//显示配置菜单
		print_config_menu(config);

		//读取用户选择
		if (scanf("%d", &choice) != 1)
		{
			//显示无效输入错误
			log_message(LOG_LEVEL_ERROR, "无效输入(请输入一个数字)");
			//清除输入缓冲区
			while (getchar() != '\n');

			//继续循环
			continue;
		}
		//清除输入缓冲区
		while (getchar() != '\n');



		switch (choice)
		{
			//切换详细输出
		case 1:
			config->verbose_output = !config->verbose_output;
			log_message(LOG_LEVEL_INFO, "详细输出: %s\r\n", config->verbose_output ? "已启用" : "已禁用");
			break;
			//JSON REP
		case 2:
			config->generation_json_report = !config->generation_json_report;
			log_message(LOG_LEVEL_INFO, "详细输出: %s\r\n", config->generation_json_report ? "已启用" : "已禁用");

			break;
			//HTML REP
		case 3:
			config->generation_html_report = !config->generation_html_report;
			log_message(LOG_LEVEL_INFO, "详细输出: %s\r\n", config->generation_html_report ? "已启用" : "已禁用");

			break;
			//修改输出目录
		case 4:
			printf("请输入输出目录(当前: %s)",config->output_directory);
			if (fgets(input,sizeof(input),stdin))
			{
				input[strcspn(input, "\n")] = '\0';
				if (strlen(input)>0&&is_valid_output_path(input))
				{
					strncpy(config->output_directory, input, MAX_PATH - 1);
					log_message(LOG_LEVEL_INFO, "输出目录以及更新为: %s", config->output_directory);


				}
				

			}
			break;
			//修改熵值阈值
		case 5:
			printf("请输入熵值阈值大小(0.0/当前: %.2f)", config->entropy_threshold);

			if (fgets(input, sizeof(input), stdin))
			{
				double threshlod = atoi(input);

				if (threshlod >= 1 && threshlod <= 8.0)
				{
					config->entropy_threshold = threshlod;
					log_message(LOG_LEVEL_INFO, "熵值阈值更新为:%u", config->entropy_threshold);


				}
				else {

					log_message(LOG_LEVEL_ERROR, "无效的熵值阈值(0.0 -8.0)");


				}




			}


			
			break;
			//修改洞穴大小
		case 6:

			printf("请输入最小洞穴大小(1-1024/当前: %u)", config->min_cave_size);

			if (fgets(input, sizeof(input), stdin))
			{
				int size = atoi(input);

				if (size >= 1 && size <= 1024)
				{
					config->min_cave_size = size;
					log_message(LOG_LEVEL_INFO, "最小洞穴大小更新为:%u", config->log_level);


				}
				else {

					log_message(LOG_LEVEL_ERROR, "无效的洞穴大小(0 -1024)");


				}




			}


			break;
			//修改日志级别
		case 7:
			printf("请输入日志级别(0 = DEBUG /1 =INFO /2 =WARNING /3 =ERROR)当前: %u\r\n",config->log_level);
			if (fgets(input,sizeof(input),stdin))
			{
				int lever = atoi(input);
				if (lever>=0&&lever<=3)
				{
					config->log_level = lever;
					Set_log_level(lever);

					log_message(LOG_LEVEL_INFO, "日志级别已更新为: %u", config->log_level);

				}
				else {


					log_message(LOG_LEVEL_ERROR, "无效的日志级别(0-3)");

				}



			}
			break;
			//返回主菜单
		case 8:
			return;


		default:
			//显示无效选项错误
			log_message(LOG_LEVEL_ERROR, "无效选项(请输入1 -8)");


			break;
		}
	}





}



/*
@brief 分析单个文件
@detail 提醒用户输入文件路径 执行PE文件分析 生成并保存报告
@param message 配置结构体指针


*/
void analyze_single_file(config_t* config) {

	//定义文件路径缓冲区

	char filename[MAX_PATH] = { 0 };

	//提醒用户输入文件路径
	printf("\n请输入 PE 文件路径: ");
	//读取文件路径
	if (!fgets(filename,sizeof(filename),stdin))
	{

		log_message(LOG_LEVEL_ERROR, "读取文件路径错误");
		return;


	}
	//移除换行符
	filename[strcspn(filename,"\n")] = '\0';

	//检测文件是否存在
	if (!file_exists(filename))
	{


		log_message(LOG_LEVEL_ERROR, "文件不存在");
		return;

	}


	//检测是否为PE文件

	if (!is_pe_file(filename))
	{
		if (!get_user_confiemation("文件可能不是 PE 文件格式是否继续"))
		{

			return;
		}


	}


	//显示开始分析
	log_message(LOG_LEVEL_INFO,"开始分析: %s", filename);
	


	//定义分析报告结构
	analysis_report_t report = { 0 };
	

	//执行文件分析
	analysis_result_t result = analyze_file(filename, &report);
	if (result != RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_ERROR, "[分析文件%s失败]", filename);
		return;
	}

	



	//生成控制台报告
	result=generate_console_report(&report,config->verbose_output);
	if (result != RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_ERROR, "[生成控制台报告%s失败]", filename);
		return;
	}
	//检查是否生成HTML报告
	if (config->generation_html_report)
	{
		analysis_result_t export_result = generate_and_open_html_report(&report, config);
		if (export_result != RESULT_SUCCESS)
		{
			log_message(LOG_LEVEL_ERROR, "[HTML report generation or open failed: %s]", filename);
		}
	}


	//检查是否生成JSON报告
	if (config->generation_json_report)
	{
		analysis_result_t export_result = generate_and_open_json_report(&report, config);
		if (export_result != RESULT_SUCCESS)
		{
			log_message(LOG_LEVEL_ERROR, "[JSON report generation or open failed: %s]", filename);
		}
	}


	





}
/*
@brief 批量分析文件
@detail 配置扫描参数 扫描文件 执行分析 生成报告
@param message 配置结构体指针


*/

void batch_analyze_files(config_t* config) {
	//初始化批量配置结构
	batch_config_t batch_config = {0};
	//初始化文件列表结构
	file_list_t file_list = { 0 };

	//初始化统计结构

	batch_statistic_t stats = {0};
	//初始化报告结构
	analysis_report_t* report = NULL;
	//提示用户输入目录
	printf("请输入要扫描的目录: ");
	if (!fgets(batch_config.directory,sizeof(batch_config.directory), stdin))
	{
		log_message(LOG_LEVEL_ERROR, "读取目录路径错误");
		return;
	}

	//移除换行符
	batch_config.directory[strcspn(batch_config.directory, "\n")] = '\0';


	//检查是否为有效目录
	
	if (!is_directroy(batch_config.directory))
	{
		log_message(LOG_LEVEL_INFO, "错误: %s 不是有效目标",batch_config.directory);

		return;
	}

	//询问是否递归扫描
	batch_config.recursive_scan = get_user_confiemation("递归扫描子目录吗?");
	
	//询问是否单独报告
	batch_config.generate_individual_report = get_user_confiemation("生成单个文件报告吗?");
	
	//询问是否汇总报告


	batch_config.generate_summary_report = get_user_confiemation("生成批量分析汇总报告吗?");
	
	//文件扫描类型选择

	printf("\n扫描文件类型选择:\n");
	printf("1. 可执行文件(EXE/DLL/SYS)\r\n");
	printf("2. 所有文件\r\n");
	printf("3. 自定义扩展名\r\n");
	printf("请输入选项(1 -3): ");

	//定义选择过滤变量
	
	int filter_chioce = 0;
	if (scanf("%d",&filter_chioce)!=1)
	{
		//显示无效输入错误
		log_message(LOG_LEVEL_INFO, "无效输入(请输入一个数字)");

		//清理输入缓冲区
		while (getchar()!='\n');

		



		return;


	}
	//清空输入缓冲区

	while (getchar() != '\n');
	//可执行文件扩展名数组
	const char* default_pe_extensions[] = { "exe","dll","sys" };

	//所有文件扩展名
	const char* all_extensions[] = { "*" };

	//自定义扩展名
	const char** selected_extensions = NULL;

	//扩展名数量
	int extension_count = 0;


	//根据用户选择设置扩展名
	switch (filter_chioce)
	{
	case 1:
		selected_extensions = default_pe_extensions;
		extension_count = 3;
		break;
	case 2:
		selected_extensions = all_extensions;
		extension_count = 1;
		break;
	case 3:
	default:
		selected_extensions = default_pe_extensions;
		extension_count = 3;
		break;
	}

	//设置批量配置扩展名
	batch_config.extensions = selected_extensions;

	//设置批量配置扩展名数量
	batch_config.extension_count = extension_count;


	//检查是否生成汇总报告
	if (batch_config.generate_summary_report)
	{
		printf("请输入汇总报告文件名(如果不输入采用默认值)");
		if (fgets(batch_config.summary_filename,sizeof(batch_config.summary_filename),stdin))
		{
			batch_config.summary_filename[strcspn(batch_config.summary_filename, "\n")] = 0;

			if (strlen(batch_config.summary_filename)==0)
			{
				strcpy(batch_config.summary_filename, "batch_analysis_summary.md");
			}



		}
	}

	//扫描目录文件
	analysis_result_t result = scan_directory_for_files(
		batch_config.directory,
		batch_config.extensions,
		batch_config.extension_count,
		batch_config.recursive_scan,
		&file_list
	);
	if (result!=RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_ERROR, "目录 [%s] 扫描失败", batch_config.directory);

		free_file_list(&file_list);


		return;
	}

	//检查是否找到文件
	if (file_list.count==0)
	{
		log_message(LOG_LEVEL_INFO, "指定目录中未匹配到对应格式文件");
		free_file_list(&file_list);
		return;
	}

	//输出匹配文件信息
	log_message(LOG_LEVEL_INFO, "匹配到 %d 个指定格式文件", file_list.count);


	//询问用户是否分析
	if (!get_user_confiemation("是否继续分析所有文件"))
	{
		free_file_list(&file_list);
		return;
	}


	//设置分析文件总数

	stats.total_files = file_list.count;
	//设置分析启动时间
	stats.start_time = time(NULL);
	//分配报告结果内存
	report = malloc(sizeof(analysis_report_t) * file_list.count);


	//检测内存分配情况

	if (!report)
	{
		log_message(LOG_LEVEL_ERROR, "汇总报告结构申请内存失败");

		free_file_list(&file_list);

		return;
	}


	//初始数据结果变量
	double total_risk_score=0;


	//遍历指定格式文件
	for (size_t i=0;i<file_list.count;i++)
	{
		uint32_t report_index = stats.successfuk_analyses;

		result = analyze_file(
			file_list.file[i],
			&report[report_index]
		);

		if (result == RESULT_SUCCESS)
		{
			stats.successfuk_analyses++;

			total_risk_score += report[report_index].overall_risk_score;
			stats.total_caves_found += report[report_index].total_cave_found;
			stats.total_anomalies_found += report[report_index].anomalies_detected;

			if (report[report_index].overall_risk_score > 70.0)
			{
				stats.hign_risk_files++;
			}

			if (batch_config.generate_individual_report)
			{
				if (config->generation_html_report)
				{
					analysis_result_t export_result =
						generate_and_open_html_report(
							&report[report_index],
							config
						);

					if (export_result != RESULT_SUCCESS)
					{
						log_message(
							LOG_LEVEL_ERROR,
							"HTML report generation failed: %s",
							report[report_index].target_file
						);
					}
				}

				if (config->generation_json_report)
				{
					analysis_result_t export_result =
						generate_and_open_json_report(
							&report[report_index],
							config
						);

					if (export_result != RESULT_SUCCESS)
					{
						log_message(
							LOG_LEVEL_ERROR,
							"JSON report generation failed: %s",
							report[report_index].target_file
						);
					}
				}
			}
		}
	}

	stats.end_time = time(NULL);
}



/*
@brief 程序入口点
@detail 初始化程序配置 启动分析引擎 进入主循环处理用户交互
@return 0表示成功 1表示失败



*/


int main(int argc, char** argv) {

	if (argc > 1)
	{
		return run_cli(argc, argv);
	}

	/*
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

	
	*/

	//打印程序横幅
	print_banner();
	//初始化配置结构
	config_t config = {
.verbose_output=true,
.generation_json_report=false,
.generation_html_report=false,
.log_level=LOG_LEVEL_INFO,
.entropy_threshold=LOW_ENTROPY_THRESHOLD,
.min_cave_size=MIN_CAVE_SIZE,
.max_cave_size=MAX_CAVE_SIZE


	};

	//设置输出目录为当前目录
	strcpy(config.output_directory, ".");
	



	

	//初始化分析引擎
	analysis_result_t result = initialize_engine(&config);

	//检查初始化是否成功

	if (result != RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_ERROR, "初始化洞穴检测系统失败(按任意键退出)");
		getchar();
		return 1;
	}


	
	//设置日志级别
	Set_log_level(config.log_level);


	//定义选择变量
	int choice = 0;

	//进入主循环
	while (1)
	{//显示主菜单
		print_menu();
		//读取用户选择
		if (scanf("%d",&choice)!=1)
		{
			//显示无效输入错误
			log_message(LOG_LEVEL_ERROR, "无效输入(请输入一个数字)");
			//清除输入缓冲区
			while (getchar() != '\n');

			//继续循环
			continue;
		}
		//清除输入缓冲区
		while (getchar() != '\n');



		switch (choice)
		{
			//分析单个文件
		case 1:
		{
			analyze_single_file(&config);

			break;
		}
		//批量分析文件
		case 2:

		{

			batch_analyze_files(&config);
			break;

		}
		//用户配置设置
		case 3:
		{
			//用户定义配置
			configure_settings(&config);
			break;

		}
		//查看使用帮助
		case 4:
		{//显示用户帮助界面
			print_help();

			break;
		}
		//退出程序执行
		case 5:
		{if (get_user_confiemation("您确定要退出吗"))
		{  //清理分析引擎
			cleanup_engine();
			//显示感谢信息
			log_message(LOG_LEVEL_INFO, "感谢使用代码洞穴使用系统");


			//返回成功代码
			return 0;
		}


			break;

		}



		default:
			//显示无效选项错误


			log_message(LOG_LEVEL_ERROR, "无效选项(请输入 1-5)");
			break;
		}



	}


	return 0;
}














