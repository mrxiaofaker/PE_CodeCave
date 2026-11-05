#ifndef ANOMALY_DETECTOR_H

#define ANOMALY_DETECTOR_H
#include "../include/common.h"
#include "../include/types.h"

analysis_result_t initialize_anmoaly_detector(VOID);

VOID cleanup_anmoaly_detector(VOID);
uint8_t get_anomaly_severity(const char* pattern_name, double confidence);
bool is_anomaly_entropy_change(double entropy1,double entropy2);
analysis_result_t  detect_entry_point_cave_cluster_anomalies(const pe_analysis_t* pe_info, const code_cave_t* caves, uint32_t cave_count, anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies);

analysis_result_t detect_cave_cluster_anomalies( const code_cave_t* caves, uint32_t cave_count, anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies);

analysis_result_t detect_entropy_anomalies(const pe_analysis_t* pe_info, anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies);
analysis_result_t detect_section_anomalies(const pe_analysis_t* pe_info,anomaly_pattern_t* anomalied, uint32_t* anomaly_count, uint32_t max_anomalies);
//异常
analysis_result_t detect_anomalies(const pe_analysis_t* pe_info,const code_cave_t*caves,uint32_t cave_count, anomaly_pattern_t* anomalied,uint32_t* anomaly_count,uint32_t max_anomalies);

#endif // !1


