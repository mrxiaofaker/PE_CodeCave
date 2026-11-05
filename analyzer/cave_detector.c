#include "cave_detector.h"
#include "..\untils\\file_tils.h"

static bool detector_initalized = false;
static config_t* detect_config = NULL;

/*
@brief 初始化代码洞穴检查器

@return 初始化结果状态码


*/
analysis_result_t initialize_cave_dectector(void)
{
	if (detector_initalized)
	{

		return RESULT_SUCCESS;
	}

	detector_initalized = true;

	return RESULT_SUCCESS;
}
/*
@brief 清理代码洞穴检查器资源




*/
void cleanup_cave_detector(void)
{
	
	detector_initalized = false;
}

/*
@brief 判断节是否为可执行节




*/
bool is_executable_section(const section_info_t* section)
{
	if (!section)
	{
		return false;
	}


	return section->is_executable;
}

/*

@brief  零填充代码洞穴检测算法
@param data 节数据指针
@param size  节数据大小
@param base_offset 节在文件中的偏移
@param section_index  节索引编号
@param caves,  输出洞穴数组
@param cave_count  输出洞穴数量
@param max_cave  最大可检测的洞穴数量
@return  分析结果状态码






*/



analysis_result_t detect_zero_fill_caves(const uint8_t*data,uint32_t size,
	uint32_t base_offset,uint32_t base_rva,uint32_t section_index,
	code_cave_t* caves,uint32_t* cave_count,uint32_t max_cave){

	/*
	
	零填充代码洞穴指的是PE文件中的连续的空字节(0x00)序列

		  编译器对其填冲

		  链接器空间优化

		  结构的对齐要求

    算法设计思路
	      状态机
	         不在洞穴中  in_cave=false
			 存在洞穴中  in_cave=true;
			 遇到     0x00  继续或者继续洞穴状态
			 遇到非   0x00  退出洞穴状态保持记录
	
	
	
	*/
	//参数校验
	if (!data||!caves||!cave_count)
	{

		return RESULT_ERROR_INVALID_PARAMETER;
	}

	//算法状态变量初始化
	*cave_count = 0;           //输出参数 检测到的洞穴数量
	uint32_t cave_start = 0;   //当前洞穴的起始地址
	uint32_t cave_size = 0;	   //当前洞穴的大小
	bool in_cave = false;      //状态机标志 正在一个洞穴  false=不在洞穴中

	//主算法循环 有限状态机实现
	for (uint32_t i=0;i<size&&*cave_count<max_cave;i++)
	{
		//检测当前字节是否为0x00
		if (data[i]==0x00)
		{
			//状态转换--遇到0字节

			if (!in_cave)
			{
				//之前不在洞穴中,现在发现了0字节

				cave_start = i;//记录洞穴起始位置
				cave_size = 1;//初始化洞穴大小为1字节
				in_cave = true;//设置状态标志

			}
			else {
				//in cave -in cave
				//之前已经在洞穴中,又遇到了一个 0字节

				//


				cave_size++;



			}






		}
		else
		{
			//状态转换- 遇到非0字节

			//检查是否需要结束当前洞穴并记录结果

			if (in_cave&&cave_size>=MIN_CAVE_SIZE)
			{
				//之前在洞穴中 并且洞穴大小阈值
				//这是一个有效的洞穴需要记录下来

				code_cave_t* cave = &caves[*cave_count];

				//填充洞穴基本信息
				cave->offset = base_offset + cave_start;
				cave->rva = base_rva + cave_start;   //绝对偏移 =节基址+相对偏移
				cave->size = cave_size;					   //洞穴大小
				cave->section_index = section_index;	   //洞穴所在节索引
				cave->cave_type = CAVE_TYPE_ZERO_FILL;	   //洞穴类型

				snprintf(cave->descriptor, sizeof(cave->descriptor),
					"[FOA] 0x%08X [RVA] 0x%08X size %u type %u",
					cave->offset, cave->rva, cave->size, cave->cave_type);

				//有效洞穴计数器累加
				(*cave_count)++;
			}
			//无论之前是否在洞穴中 ,现在都需要重置状态
			in_cave = false;
			cave_size = 0;


		}




	}




	return RESULT_SUCCESS;



      }

	  /*

	  @brief  模式填充代码洞穴检测算法
	  @param data 节数据指针
	  @param size  节数据大小
	  @param base_offset 节在文件中的偏移
	  @param section_index  节索引编号
	  @param caves,  输出洞穴数组
	  @param cave_count  输出洞穴数量
	  @param max_cave  最大可检测的洞穴数量
	  @return  分析结果状态码






	  */

	  analysis_result_t detect_pattern_fill_caves(const uint8_t* data, uint32_t size,
		  uint32_t base_offset, uint32_t base_rva, uint32_t section_index,
		  code_cave_t* caves, uint32_t* cave_count, uint32_t max_cave) {

		  /*
		  
		  0xCC   调试代码

		  0X90   nop sled

		  0xFF   未初始化校验
		  
		  //参数校验

		  
		  
		  */


		  //参数校验
		  if (!data || !caves || !cave_count)
		  {

			  return RESULT_ERROR_INVALID_PARAMETER;
		  }

		  //算法状态变量初始化
		  *cave_count = 0;           //输出参数 检测到的洞穴数量
		  
		  //定义检测模式
		  const uint8_t patterns[] = { 0xCC,0x90,0xFF };
		  const int pattern_count = sizeof(patterns) / sizeof(patterns);

		  //外层循环
		  //预定的填充模式循环遍历检测
		  for (size_t p=0;p< pattern_count;p++)
		  {
			  //当前检测的目标模式字节
			  uint8_t pattern = patterns[p];

			  //检测状态变量
			  uint32_t cave_start = 0;   //当前洞穴的起始地址
			  uint32_t cave_size = 0;	   //当前洞穴的大小
			  bool in_cave = false;      //状态机标志 正在一个洞穴  false=不在洞穴中
			  //内层循环
			  for (uint32_t i=0;i<size&&*cave_count<max_cave;i++)
			  {

				  //检测当前字节是否为pattern
				  if (data[i] == pattern)
				  {
					  //状态转换--遇到pattern

					  if (!in_cave)
					  {
						  //之前不在洞穴中,现在发现了模式匹配字节

						  cave_start = i;//记录洞穴起始位置
						  cave_size = 1;//初始化洞穴大小为1字节
						  in_cave = true;//设置状态标志

					  }
					  else {
						  //in cave -in cave
						  //之前已经在洞穴中,又遇到了一个模式匹配字节

						  //


						  cave_size++;



					  }


				  }
				  else
				  {
					  //状态转换- 遇到非模式匹配字节

					  //检查是否需要结束当前洞穴并记录结果

					  if (in_cave && cave_size >= MIN_CAVE_SIZE)
					  {
						  //之前在洞穴中 并且洞穴大小阈值
						  //这是一个有效的洞穴需要记录下来

						  //&cave[42]  -arr.base
						  code_cave_t* cave = &caves[*cave_count];

						  //填充洞穴基本信息
						  cave->offset = base_offset + cave_start;
						  cave->rva = base_rva + cave_start;   //绝对偏移 =节基址+相对偏移
						  cave->size = cave_size;					   //洞穴大小
						  cave->section_index = section_index;	   //洞穴所在节索引
						  cave->cave_type = CAVE_TYPE_PATTERN_FILL;	   //洞穴类型

						  snprintf(cave->descriptor, sizeof(cave->descriptor),
					"[FOA] 0x%08X [RVA] 0x%08X size %u type %u",
					cave->offset, cave->rva, cave->size, cave->cave_type);

						  //有效洞穴计数器累加
						  (*cave_count)++;
					  }
					  //无论之前是否在洞穴中 ,现在都需要重置状态
					  in_cave = false;
					  cave_size = 0;


				  }



			  }





		  }


		  return RESULT_SUCCESS;



	  }


	  /*

	@brief 代码洞穴威胁等级计算算法
	@param cave 评估的代码洞穴结构体指针
	@param section  代码洞穴所在节区结构体指针
	@return  威胁等级分数 0.0~1.0 之间的浮点数,越高表示威胁越大


	*/

	  double calcute_suspicion_level(const code_cave_t* cave, const section_info_t* section)
	  {
		  /*
		  xx评估理论基础
			 - 位置因子 洞穴所在的节的可执行
			 - 大小因子	    洞穴容量绝对可注入代码的复杂性
			 - 类型因子	    不同类型的洞穴可能具有不同的威胁等级
			 - 熵值因子	所在节的熵值越高,可能是加密|压缩|混淆代码,威胁等级越高
				 
		  评分算法设计
		       -基础分数        每个因子产生独立的威胁数量
			   -权重设计        因子权重
			   -归一化          分数规范到[0.0~1.0]
			   -阀值控制        划分威胁等级区间
		  因子权重分析
			
		  位置因子(0.4)    洞穴所在的节的可执行
		  大小因子(0.1~0.3)    洞穴容量绝对可注入代码的复杂性
		  类型因子(0.1~0.3)    不同类型的洞穴可能具有不同的威胁等级
		  熵值因子(0.2)    所在节的熵值越高,可能是加密|压缩|混淆代码,威胁等级越高
		  
		  威胁等级映射区间
		 - 0.0~0.3  低风险     正常编译产生
		 - 0.3~0.6  中等风险   需要关注
		 - 0.6~0.8  高风险     可能的攻击弥补
		 - 0.8~1.0  极高风险   严重的恶意利用

		  
		  */
		  //参数验证

		  if (!cave || !section)
		  {
			  return RESULT_ERROR_INVALID_PARAMETER;
		  }
		  //威胁等级变量初始化
		  double suspicion = 0.0;

		  //因子1- 节的可执行评估
		  if (is_executable_section(section))
		  {

			  suspicion += 0.4;
			  //.text .code .page 这些节通常是可执行的,如果洞穴出现在这些节中,可能是恶意代码注入的迹象
		  }

		  //因子2- 洞穴大小评估
		  if (cave->size>32)
		  {

			  suspicion += 0.3;
			  //完整的模块功能
		  }
		  else if (cave->size>16)
		  {
			  suspicion += 0.2;
			  //简单的恶意功能
		  }
		  else
		  {
			  suspicion += 0.1;
			  //调整指令或在hook中注入代码
		  }

		  //洞穴类型评估
		  switch (cave->cave_type)
		  {
			  case CAVE_TYPE_ZERO_FILL:
				  suspicion += 0.2;
				  break;

			  case CAVE_TYPE_PATTERN_FILL:
				  suspicion += 0.1;
				  //0xcc 调试残留
				  //0x90 nop指令区域
				  //0xFF 初始化数据

				  break;
			  case CAVE_TYPE_SECTION_GAP:
				  suspicion += 0.3;
				  //节区间隙可能包含未初始化数据,调试信息或其他不相关数据,可能是隐藏的恶意代码
				  break;

		  default:
			  break;

			  return suspicion;

		  }


		  //节数据的熵值评估
		  if (section->entropy<LOW_ENTROPY_THRESHOLD)
		  {

			  suspicion += 0.2;
			  
		  }
		 
		 


		  return (suspicion>1.0)?1.0: suspicion;
	  }




	  /*

	  节区间隙检测算法

	  1.节区间隙是指PE文件中两个节区之间的未使用空间
	  2.这些间隙可能包含未初始化的数据、调试信息或其他不相关的数据
	  3.检测节区间隙有助于发现潜在的代码洞穴或隐藏的恶意代码

	  算法设计思路:

	  1.遍历所有节区，按文件偏移排序
	  2.计算相邻节区之间的间隙大小
	  3.如果间隙大小大于等于最小洞穴大小阈值，则记录为一个代码洞穴
	  */
	  /*

	  @brief  节区间隙检测算法
	  @param pe_info PE文件分析信息结构体指针
	  @param caves 输出洞穴数组
	  @param cave_count 输出洞穴数量
	  @param max_caves 最大可检测的洞穴数量
	  @return  分析结果状态码

	  */
	  analysis_result_t detect_section_gaps(const pe_analysis_t* pe_info, 
		  code_cave_t* caves, uint32_t* cave_count, uint32_t max_caves) {
		  //参数验证
		  if (!pe_info||!caves||!cave_count)
		  {
			  return RESULT_ERROR_INVALID_PARAMETER;
		  }

		  //算法状态变量初始化
		  *cave_count = 0; //输出参数 检测到的洞穴数量

		  //相邻节区间隙检测循环
		  for (uint32_t i=0;i+1<pe_info->section_count&&*cave_count<max_caves;i++)
		  {
			  //当前节区
			  const section_info_t* current = &pe_info->section[i];



			  //下一个节
			  const section_info_t* next = &pe_info->section[i + 1];

			  //过滤无效节区
			  if (current->raw_address==0||next->raw_address==0)
			  {

				  continue;

			  }
			  //计算节区间隙
			  uint32_t current_end = current->virtual_address + current->virtual_size;
			  if (current_end > next->virtual_address)
			  {
				  continue;
			  }
			  uint32_t gap_size = next->virtual_address - current_end;

			  //间隙有效性检查
			  if (gap_size>=MIN_CAVE_SIZE&&gap_size<=MAX_CAVE_SIZE)
			  {
				  code_cave_t* cave = &caves[*cave_count];
				  uint32_t gap_offset = current_end - current->virtual_address;
				  cave->offset = gap_offset < current->raw_size
					  ? current->raw_address + gap_offset
					  : 0;
				  cave->rva = current_end;
				  cave->size = gap_size;
				  cave->section_index = i;
				  cave->cave_type = CAVE_TYPE_SECTION_GAP;

				  snprintf(cave->descriptor, sizeof(cave->descriptor),
					"[FOA] 0x%08X [RVA] 0x%08X size %u type %u",
					cave->offset, cave->rva, cave->size, cave->cave_type);
				 


				  (*cave_count)++;

			  }



		  }

		  return RESULT_SUCCESS;



	  }
	  


/*

@brief  检测代码洞穴主函数
@param pe_info PE文件分析信息结构体指针
@param cave  用于存储检测结果的数组
@param cave_count 检测到的洞穴数量的指针
@param max_cave  最大可检测的洞穴数量
@return  分析结果状态码






*/
analysis_result_t detect_code_caves(const pe_analysis_t* pe_info, code_cave_t* cave, uint32_t* cave_count, uint32_t max_caves)
{ 
	//参数校验
	if (!detector_initalized||!pe_info||!cave||!cave_count)
	{


		return RESULT_ERROR_INVALID_PARAMETER;

	}
	//初始化检测结果计数器
	*cave_count = 0;


	//获取文件数据
	uint8_t* file_data = NULL;


	uint32_t file_size = 0;


	analysis_result_t result=read_file_to_memory(pe_info->filename, &file_data, &file_size);

	if (result !=RESULT_SUCCESS)
	{

		return result;

	}
	//节区洞穴检测循环

	for (uint32_t i=0;i<pe_info->section_count&&*cave_count<max_caves;i++)
	{
		//节属性
		//--------------------------------------------------------
		//获取节区信息
		const section_info_t* section = &pe_info->section[i];

		//过滤文件空节区
		if (section->raw_address==0||section->raw_size==0)
		{


			continue;
		}

		//零填充代码洞穴检测
		//--------------------------------------------------------
		uint32_t section_caves = 0;
		uint32_t remaing_slots = max_caves - *cave_count;


		//边界检查
		if (section->raw_address<=file_size&&section->raw_size<=file_size-section->raw_address)
		{
			//零填充扫描
			result = detect_zero_fill_caves(file_data + section->raw_address,
				section->raw_size,
				section->raw_address,
				section->virtual_address,
				i,
				&cave[*cave_count],//
				& section_caves,
				remaing_slots
			);




		}
		else
		{


			result = RESULT_SUCCESS;
			section_caves = 0;

		}

		if (result == RESULT_SUCCESS)
		{

			*cave_count += section_caves;

		}
		if (*cave_count>=max_caves)
		{


			break;

		}
		//模式填充代码洞穴检测
		//--------------------------------------------------------

		section_caves = 0;
		remaing_slots = max_caves - *cave_count;


		//边界检查
		if (section->raw_address <= file_size && section->raw_size <= file_size - section->raw_address)
		{
			//模式填充扫描
			result = detect_pattern_fill_caves(file_data + section->raw_address,
				section->raw_size,
				section->raw_address,
				section->virtual_address,
				i,
				&cave[*cave_count],//
				&section_caves,
				remaing_slots
			);




		}
		else
		{


			result = RESULT_SUCCESS;
			section_caves = 0;

		}

		if (result == RESULT_SUCCESS)
		{

			*cave_count += section_caves;

		}
		if (*cave_count >= max_caves)
		{


			break;

		}

	}


	//节区间隙检测

	if (*cave_count<max_caves)
	{
		uint32_t gap_caves = 0;
		uint32_t remaining_slots = max_caves - *cave_count;

	result=	detect_section_gaps(pe_info, &cave[*cave_count], &gap_caves, remaining_slots);


	if (result==RESULT_SUCCESS)
	{
		*cave_count += gap_caves;
	}




	}
	//洞穴风险评估


	for (uint32_t i = 0; i < *cave_count; i++)
	{

		const section_info_t* section = &pe_info->section[cave[i].section_index];

		cave[i].suspicion_level = calcute_suspicion_level(&cave[i], section);
	}

	SAFE_FREE(file_data);




	return RESULT_SUCCESS;

}

