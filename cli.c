#define _CRT_SECURE_NO_WARNINGS

#include "cli.h"
#include "core/engine.h"
#include "parser/pe_parser.h"
#include "reporter/report_generator.h"
#include "untils/file_tils.h"

#define CLI_MAX_EXTENSIONS 32
#define CLI_MAX_EXTENSION_LENGTH 32

typedef struct
{
	char target_file[MAX_PATH];
	int analysis_status;
	int report_status;
	uint32_t cave_count;
	uint32_t anomaly_count;
	char message[160];
} cli_result_t;

static void print_cli_help(FILE* stream)
{
	fputs(
		"PE CodeCave - static PE code-cave and structural anomaly scanner\n"
		"\n"
		"Usage:\n"
		"  PE_CodeCave.exe --path <file-or-directory> [options]\n"
		"  PE_CodeCave.exe <file-or-directory> [options]\n"
		"\n"
		"Options:\n"
		"  --path <path>          File or directory to analyze\n"
		"  --recursive            Recurse into subdirectories\n"
		"  --extensions <list>    Comma-separated extensions (default: exe,dll,sys)\n"
		"  --html                 Generate an HTML report for each file\n"
		"  --json                 Generate a JSON report for each file\n"
		"  --out <directory>      Report and batch summary directory (default: .)\n"
		"  --quiet                Suppress per-file console details\n"
		"  --verbose              Show per-file console details (default)\n"
		"  --help, -h             Show this help\n"
		"  --version              Show version\n"
		"\n"
		"Directory mode always writes batch_summary.csv to the output directory.\n"
		"Reports use the pe-codecave.report.v1 JSON schema.\n"
		"\n"
		"Examples:\n"
		"  PE_CodeCave.exe --path sample.exe --json --out reports\n"
		"  PE_CodeCave.exe --path samples --recursive --extensions exe,dll,sys "
		"--html --json --out reports\n",
		stream);
}

static void set_cli_defaults(config_t* config, const char* output_directory,
	bool html, bool json, bool quiet)
{
	memset(config, 0, sizeof(*config));
	config->verbose_output = !quiet;
	config->generation_json_report = json;
	config->generation_html_report = html;
	config->log_level = quiet ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO;
	config->entropy_threshold = LOW_ENTROPY_THRESHOLD;
	config->min_cave_size = MIN_CAVE_SIZE;
	config->max_cave_size = MAX_CAVE_SIZE;
	strncpy(config->output_directory, output_directory, MAX_PATH - 1);
	config->output_directory[MAX_PATH - 1] = '\0';
}

static bool path_is_directory(const char* path)
{
	DWORD attributes = GetFileAttributesA(path);
	return attributes != INVALID_FILE_ATTRIBUTES
		&& (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static bool create_directory_tree(const char* path)
{
	char buffer[MAX_PATH];
	char* cursor;

	if (!path || !path[0])
	{
		return false;
	}
	if (path_is_directory(path))
	{
		return true;
	}
	if (strlen(path) >= sizeof(buffer))
	{
		return false;
	}

	strcpy(buffer, path);
	cursor = buffer;
	if (buffer[0] != '\0' && buffer[1] == ':')
	{
		cursor = buffer + 2;
	}

	for (; *cursor; cursor++)
	{
		if (*cursor == '\\' || *cursor == '/')
		{
			char separator = *cursor;
			*cursor = '\0';
			if (buffer[0])
			{
				CreateDirectoryA(buffer, NULL);
			}
			*cursor = separator;
		}
	}

	if (!CreateDirectoryA(buffer, NULL)
		&& GetLastError() != ERROR_ALREADY_EXISTS)
	{
		return false;
	}

	return path_is_directory(buffer);
}

static int parse_extensions(const char* specification, char storage[][CLI_MAX_EXTENSION_LENGTH],
	const char** extensions)
{
	char* copy;
	char* context = NULL;
	char* token;
	int count = 0;

	if (!specification || !specification[0])
	{
		return 0;
	}

	copy = _strdup(specification);
	if (!copy)
	{
		return -1;
	}

	token = strtok_s(copy, ",;", &context);
	while (token && count < CLI_MAX_EXTENSIONS)
	{
		char* begin = token;
		char* end;

		while (*begin == ' ' || *begin == '\t')
		{
			begin++;
		}
		end = begin + strlen(begin);
		while (end > begin && (end[-1] == ' ' || end[-1] == '\t'))
		{
			*--end = '\0';
		}
		if (begin[0] == '*')
		{
			strcpy(storage[count], "*");
		}
		else
		{
			if (begin[0] == '.')
			{
				begin++;
			}
			if (begin[0] == '*' && begin[1] == '.')
			{
				begin += 2;
			}
			if (!begin[0] || strlen(begin) >= CLI_MAX_EXTENSION_LENGTH)
			{
				token = strtok_s(NULL, ",;", &context);
				continue;
			}
			strcpy(storage[count], begin);
		}
		extensions[count] = storage[count];
		count++;
		token = strtok_s(NULL, ",;", &context);
	}

	free(copy);
	return count;
}

static void write_csv_escaped(FILE* file, const char* text)
{
	bool needs_quotes = false;
	const char* cursor;

	if (!text)
	{
		text = "";
	}
	for (cursor = text; *cursor; cursor++)
	{
		if (*cursor == ',' || *cursor == '"' || *cursor == '\r' || *cursor == '\n')
		{
			needs_quotes = true;
			break;
		}
	}

	if (!needs_quotes)
	{
		fputs(text, file);
		return;
	}

	fputc('"', file);
	for (cursor = text; *cursor; cursor++)
	{
		if (*cursor == '"')
		{
			fputc('"', file);
		}
		fputc(*cursor, file);
	}
	fputc('"', file);
}

static bool write_batch_summary(const char* output_directory, const cli_result_t* results,
	uint32_t result_count)
{
	char summary_path[MAX_PATH];
	FILE* file;
	uint32_t i;

	if (snprintf(summary_path, sizeof(summary_path), "%s\\batch_summary.csv",
		output_directory) >= (int)sizeof(summary_path))
	{
		return false;
	}

	file = fopen(summary_path, "wb");
	if (!file)
	{
		return false;
	}

	fputs("\xEF\xBB\xBF", file);
	fputs("target_file,analysis_status,report_status,cave_count,anomaly_count,message\n", file);
	for (i = 0; i < result_count; i++)
	{
		write_csv_escaped(file, results[i].target_file);
		fprintf(file, ",%d,%d,%u,%u,", results[i].analysis_status,
			results[i].report_status, results[i].cave_count,
			results[i].anomaly_count);
		write_csv_escaped(file, results[i].message);
		fputc('\n', file);
	}

	fclose(file);
	printf("Batch summary: %s\n", summary_path);
	return true;
}

static int analyze_cli_file(const char* filename, const config_t* config, bool quiet,
	cli_result_t* result)
{
	analysis_report_t* report;
	analysis_result_t analysis_status;
	analysis_result_t report_status = RESULT_SUCCESS;

	memset(result, 0, sizeof(*result));
	strncpy(result->target_file, filename, MAX_PATH - 1);

	report = (analysis_report_t*)calloc(1, sizeof(*report));
	if (!report)
	{
		result->analysis_status = RESULT_ERROR_MEMORY_ALLOCATION;
		strcpy(result->message, "memory allocation failed");
		return result->analysis_status;
	}

	analysis_status = analyze_file(filename, report);
	result->analysis_status = analysis_status;
	if (analysis_status == RESULT_SUCCESS)
	{
		result->cave_count = report->total_cave_found;
		result->anomaly_count = report->anomalies_detected;

		if (!quiet)
		{
			analysis_result_t console_status =
				generate_console_report(report, config->verbose_output);
			if (console_status != RESULT_SUCCESS)
			{
				report_status = console_status;
				strcpy(result->message, "console report failed");
			}
		}

		if (config->generation_html_report)
		{
			analysis_result_t html_status = generate_html_report(report, config);
			if (html_status != RESULT_SUCCESS)
			{
				report_status = html_status;
				strcpy(result->message, "HTML report failed");
			}
		}

		if (config->generation_json_report)
		{
			analysis_result_t json_status = generate_json_report(report, config);
			if (json_status != RESULT_SUCCESS)
			{
				report_status = json_status;
				strcpy(result->message, "JSON report failed");
			}
		}
	}
	else
	{
		snprintf(result->message, sizeof(result->message),
			"analysis failed with code %d", analysis_status);
	}

	result->report_status = report_status;
	SAFE_FREE(report->pe_info.section);
	SAFE_FREE(report);
	return analysis_status;
}

int run_cli(int argc, char** argv)
{
	const char* path = NULL;
	const char* output_directory = ".";
	const char* extension_specification = "exe,dll,sys";
	bool recursive = false;
	bool html = false;
	bool json = false;
	bool quiet = false;
	char extension_storage[CLI_MAX_EXTENSIONS][CLI_MAX_EXTENSION_LENGTH];
	const char* extensions[CLI_MAX_EXTENSIONS];
	int extension_count;
	file_list_t files = { 0 };
	cli_result_t* results = NULL;
	config_t config;
	analysis_result_t scan_status;
	uint32_t succeeded = 0;
	uint32_t failed = 0;
	uint32_t i;
	int exit_code = 0;

	for (i = 1; i < (uint32_t)argc; i++)
	{
		const char* argument = argv[i];

		if (_stricmp(argument, "--help") == 0 || _stricmp(argument, "-h") == 0)
		{
			print_cli_help(stdout);
			return 0;
		}
		else if (_stricmp(argument, "--version") == 0)
		{
			printf("PE CodeCave 1.0.0\n");
			return 0;
		}
		else if (_stricmp(argument, "--path") == 0 && i + 1 < (uint32_t)argc)
		{
			path = argv[++i];
		}
		else if (_stricmp(argument, "--out") == 0 && i + 1 < (uint32_t)argc)
		{
			output_directory = argv[++i];
		}
		else if (_stricmp(argument, "--extensions") == 0 && i + 1 < (uint32_t)argc)
		{
			extension_specification = argv[++i];
		}
		else if (_stricmp(argument, "--recursive") == 0)
		{
			recursive = true;
		}
		else if (_stricmp(argument, "--html") == 0)
		{
			html = true;
		}
		else if (_stricmp(argument, "--json") == 0)
		{
			json = true;
		}
		else if (_stricmp(argument, "--quiet") == 0)
		{
			quiet = true;
		}
		else if (_stricmp(argument, "--verbose") == 0)
		{
			quiet = false;
		}
		else if (argument[0] == '-')
		{
			fprintf(stderr, "error: unknown option: %s\n", argument);
			print_cli_help(stderr);
			return 2;
		}
		else if (!path)
		{
			path = argument;
		}
		else
		{
			fprintf(stderr, "error: unexpected argument: %s\n", argument);
			return 2;
		}
	}

	if (!path)
	{
		fprintf(stderr, "error: --path is required\n\n");
		print_cli_help(stderr);
		return 2;
	}

	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES)
	{
		fprintf(stderr, "error: path does not exist: %s\n", path);
		return 2;
	}
	if (!create_directory_tree(output_directory))
	{
		fprintf(stderr, "error: cannot create output directory: %s\n",
			output_directory);
		return 2;
	}

	extension_count = parse_extensions(extension_specification, extension_storage,
		extensions);
	if (extension_count <= 0)
	{
		fprintf(stderr, "error: no valid extensions were supplied\n");
		return 2;
	}

	set_cli_defaults(&config, output_directory, html, json, quiet);
	Set_log_level(config.log_level);

	if (initialize_engine(&config) != RESULT_SUCCESS)
	{
		fprintf(stderr, "error: failed to initialize analysis engine\n");
		return 1;
	}

	if (path_is_directory(path))
	{
		printf("Scanning directory: %s\n", path);
		scan_status = scan_directory_for_files(path, extensions, extension_count,
			recursive, &files);
	}
	else
	{
		scan_status = add_file_to_list(&files, path);
	}

	if (scan_status != RESULT_SUCCESS)
	{
		fprintf(stderr, "error: failed to enumerate input files (code %d)\n",
			scan_status);
		cleanup_engine();
		return 1;
	}
	if (files.count == 0)
	{
		fprintf(stderr, "error: no matching files were found\n");
		cleanup_engine();
		free_file_list(&files);
		return 1;
	}

	results = (cli_result_t*)calloc(files.count, sizeof(*results));
	if (!results)
	{
		fprintf(stderr, "error: memory allocation failed\n");
		cleanup_engine();
		free_file_list(&files);
		return 1;
	}

	printf("Matched files: %u\n", files.count);
	for (i = 0; i < files.count; i++)
	{
		if (!quiet)
		{
			printf("\n[%u/%u] %s\n", i + 1, files.count, files.file[i]);
		}
		if (analyze_cli_file(files.file[i], &config, quiet, &results[i])
			== RESULT_SUCCESS)
		{
			succeeded++;
		}
		else
		{
			failed++;
		}
	}

	if (path_is_directory(path)
		&& !write_batch_summary(output_directory, results, files.count))
	{
		fprintf(stderr, "error: failed to write batch_summary.csv\n");
		exit_code = 1;
	}

	printf("Completed: %u succeeded, %u failed\n", succeeded, failed);
	if (failed > 0)
	{
		exit_code = 1;
	}

	SAFE_FREE(results);
	free_file_list(&files);
	cleanup_engine();
	return exit_code;
}
