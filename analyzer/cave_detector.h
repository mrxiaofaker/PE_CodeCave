#ifndef CAVE_DETECOTR_H

#define CAVE_DETECOTR_H
#include "../include/common.h"
#include "../include/types.h"

analysis_result_t initialize_cave_dectector(void);

void cleanup_cave_detector(void);

bool is_executable_section(const section_info_t* section);
analysis_result_t detect_zero_fill_caves(const uint8_t* data, uint32_t size,uint32_t base_offset, uint32_t base_rva, uint32_t section_index,code_cave_t* caves, uint32_t* cave_count, uint32_t max_cave);

analysis_result_t  detect_code_caves(const pe_analysis_t* pe_info, code_cave_t* cave, uint32_t* cave_count, uint32_t max_caves);
analysis_result_t detect_pattern_fill_caves(const uint8_t* data, uint32_t size,uint32_t base_offset, uint32_t base_rva, uint32_t section_index,
code_cave_t* caves, uint32_t* cave_count, uint32_t max_cave);

double calcute_suspicion_level(const code_cave_t* cave, const section_info_t* section);

analysis_result_t detect_section_gaps(const pe_analysis_t* pe_info, code_cave_t* caves, uint32_t* cave_count, uint32_t max_caves);




#endif // !1


