#ifndef PE_PARSER_H
#define PE_PARSER_H
#include "../include/common.h"
#include "../include/types.h"

analysis_result_t initialize_pe_parser(void);



void clean_pe_parser(void);

analysis_result_t validate_pe_structure(const uint8_t* file_data,uint32_t file_size);

analysis_result_t parse_dos_header(const uint8_t* file_data, IMAGE_DOS_HEADER* dos_header);

analysis_result_t parse_nt_header(const uint8_t* file_data, uint32_t nt_offset, IMAGE_NT_HEADERS*nt_header);

analysis_result_t parse_section(const uint8_t*file_data,uint32_t file_size,uint32_t nt_header_offset
,const IMAGE_NT_HEADERS*nt_headers,section_info_t**sections,uint16_t*section_count);


double calcuate_entropy(const uint8_t* data, uint32_t size);

void free_file_list(file_list_t* file_list);

analysis_result_t parse_pe_file(const char* filename, pe_analysis_t* pe_info);


#endif // !1


