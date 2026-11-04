#ifndef ENGINE_H

#define ENGINE_H 

#include "../include/common.h"

#include "../include/types.h"



void log_message(uint8_t level, const char* format, ...);

void Set_log_level(uint8_t level);
analysis_result_t initialize_engine(config_t* config);

void cleanup_engine(void);


analysis_result_t  analyze_file(const char* filename, analysis_report_t* report);
#endif
