#ifndef REPORT_GENERTOR
#define REPORT_GENERTOR
#include "../include/common.h"
#include "../include/types.h"

void  print_anomaly_pattern_info(const anomaly_pattern_t* anomalies, uint32_t anomaly_count, BOOL verbose);
void  print_caves_info(const code_cave_t* caves, uint32_t cave_count, bool verbose);
void print_pe_struct_info(const analysis_report_t* report);
void print_report_summary(const analysis_report_t* report);
analysis_result_t generate_console_report(const analysis_report_t* report,bool verbose);
analysis_result_t generate_html_report(const analysis_report_t* report, const config_t* config);
analysis_result_t generate_json_report(const analysis_report_t* report, const config_t* config);
analysis_result_t generate_and_open_html_report(const analysis_report_t* report, const config_t* config);
analysis_result_t generate_and_open_json_report(const analysis_report_t* report, const config_t* config);


#endif // !1
