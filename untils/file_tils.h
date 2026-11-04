#ifndef FILE_TILS_H
#define FILE_TILS_H
#include "../include/common.h"
#include "../include/types.h"


BOOL is_valid_output_path(const char* path);



const char* get_file_extension(const char* filename);
BOOL file_exists(const char* filename);


analysis_result_t scan_directory_for_files(const char* directory, const char** extensions, int ext_count, bool recursive, file_list_t* file_list);



BOOL is_pe_file(const char* filename);

analysis_result_t get_file_size(const char* filename, uint32_t* size);

analysis_result_t read_file_to_memory(const char* filename, uint8_t** data, uint32_t* size);
bool matches_extension(const char* filename, const char** extensions, int ext_count);
analysis_result_t add_file_to_list(file_list_t* file_list, const char* filename);
bool is_directroy(const char* path);


#endif // !1