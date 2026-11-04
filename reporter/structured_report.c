#define _CRT_SECURE_NO_WARNINGS
#include "report_generator.h"
#include "../core/engine.h"
#include <ctype.h>
#include <shellapi.h>

#pragma comment(lib, "shell32.lib")

#define REPORT_SCHEMA_VERSION "pe-codecave.report.v1"
#define REPORT_HIGH_RISK_THRESHOLD 0.60

#define HTML_LBL_SECURITY_REPORT \
	"&#23433;&#20840;&#20998;&#26512;&#25253;&#21578;"
#define HTML_LBL_RISK_SCORE \
	"&#39118;&#38505;&#35780;&#20998;"
#define HTML_LBL_CODE_CAVES \
	"&#20195;&#30721;&#27934;&#31348;"
#define HTML_LBL_HIGH_RISK_CAVES \
	"&#39640;&#21361;&#27934;&#31348;"
#define HTML_LBL_ANOMALIES \
	"&#24322;&#24120;&#21457;&#29616;"
#define HTML_LBL_SECTIONS \
	"PE &#33410;&#21306;"
#define HTML_LBL_OVERALL_ENTROPY \
	"&#25972;&#20307;&#29109;&#20540;"
#define HTML_LBL_SECTION_ENTROPY \
	"&#33410;&#21306;&#29109;&#20540;&#20998;&#24067;"
#define HTML_LBL_CAVE_LIST \
	"&#20195;&#30721;&#27934;&#31348;&#28165;&#21333;"
#define HTML_LBL_ANOMALY_PATTERNS \
	"&#24322;&#24120;&#27169;&#24335;"
#define HTML_LBL_RECOMMENDATIONS \
	"&#22788;&#32622;&#24314;&#35758;"
#define HTML_LBL_CONCLUSION \
	"&#26816;&#27979;&#32467;&#35770;"
#define HTML_LBL_GENERATED_AT \
	"&#29983;&#25104;&#26102;&#38388;"
#define HTML_LBL_TARGET_FILE \
	"&#30446;&#26631;&#25991;&#20214;"
#define HTML_LBL_ALL \
	"&#20840;&#37096;"
#define HTML_LBL_SEARCH \
	"&#25628;&#32034;"
#define HTML_LBL_NO_FINDINGS \
	"&#26080;&#21457;&#29616;"

typedef struct
{
	uint32_t cave_count;
	uint32_t anomaly_count;
	uint32_t high_risk_caves;
	uint32_t zero_fill_caves;
	uint32_t pattern_fill_caves;
	uint32_t gap_caves;
	uint32_t overlay_caves;
	uint32_t total_cave_bytes;
	uint32_t rwx_sections;
	uint32_t executable_sections;
	uint32_t severity_counts[5];
	double max_suspicion;
	double average_suspicion;
	double cave_component;
	double anomaly_component;
	double section_component;
	int risk_score;
	const char* risk_grade;
	const char* risk_class;
} report_stats_t;

static size_t bounded_length(const char* text, size_t limit)
{
	size_t length = 0;

	if (!text)
	{
		return 0;
	}

	while (length < limit && text[length] != '\0')
	{
		length++;
	}

	return length;
}

static char* allocate_empty_string(void)
{
	char* empty = (char*)calloc(1, sizeof(char));
	return empty;
}

/*
Convert strings produced by this ANSI C application into UTF-8 without
changing the caller's data. This keeps Chinese paths/descriptors valid in
the generated JSON and HTML files.
*/
static char* acp_to_utf8(const char* source, size_t source_limit)
{
	size_t source_length;
	int wide_length;
	int utf8_length;
	wchar_t* wide_text;
	char* utf8_text;

	if (!source)
	{
		return allocate_empty_string();
	}

	source_length = bounded_length(source, source_limit);
	if (source_length == 0)
	{
		return allocate_empty_string();
	}

	wide_length = MultiByteToWideChar(
		CP_ACP,
		0,
		source,
		(int)source_length,
		NULL,
		0);
	if (wide_length <= 0)
	{
		return allocate_empty_string();
	}

	wide_text = (wchar_t*)calloc((size_t)wide_length + 1, sizeof(wchar_t));
	if (!wide_text)
	{
		return NULL;
	}

	if (MultiByteToWideChar(
		CP_ACP,
		0,
		source,
		(int)source_length,
		wide_text,
		wide_length) <= 0)
	{
		free(wide_text);
		return allocate_empty_string();
	}

	utf8_length = WideCharToMultiByte(
		CP_UTF8,
		0,
		wide_text,
		wide_length,
		NULL,
		0,
		NULL,
		NULL);
	if (utf8_length <= 0)
	{
		free(wide_text);
		return allocate_empty_string();
	}

	utf8_text = (char*)calloc((size_t)utf8_length + 1, sizeof(char));
	if (!utf8_text)
	{
		free(wide_text);
		return NULL;
	}

	if (WideCharToMultiByte(
		CP_UTF8,
		0,
		wide_text,
		wide_length,
		utf8_text,
		utf8_length,
		NULL,
		NULL) <= 0)
	{
		free(wide_text);
		free(utf8_text);
		return allocate_empty_string();
	}

	free(wide_text);
	return utf8_text;
}

static void write_html_text(FILE* file, const char* source, size_t source_limit)
{
	char* utf8_text;
	const unsigned char* cursor;

	if (!file)
	{
		return;
	}

	utf8_text = acp_to_utf8(source, source_limit);
	if (!utf8_text)
	{
		return;
	}

	cursor = (const unsigned char*)utf8_text;
	while (*cursor)
	{
		switch (*cursor)
		{
		case '&':
			fputs("&amp;", file);
			break;
		case '<':
			fputs("&lt;", file);
			break;
		case '>':
			fputs("&gt;", file);
			break;
		case '"':
			fputs("&quot;", file);
			break;
		case '\'':
			fputs("&#39;", file);
			break;
		default:
			if (*cursor < 0x20 && *cursor != '\t' && *cursor != '\n')
			{
				fputc(' ', file);
			}
			else
			{
				fputc((int)*cursor, file);
			}
			break;
		}
		cursor++;
	}

	free(utf8_text);
}

static void write_json_escaped(FILE* file, const char* source, size_t source_limit)
{
	char* utf8_text;
	const unsigned char* cursor;

	if (!file)
	{
		return;
	}

	utf8_text = acp_to_utf8(source, source_limit);
	if (!utf8_text)
	{
		fputs("\"\"", file);
		return;
	}

	fputc('"', file);
	cursor = (const unsigned char*)utf8_text;
	while (*cursor)
	{
		switch (*cursor)
		{
		case '"':
			fputs("\\\"", file);
			break;
		case '\\':
			fputs("\\\\", file);
			break;
		case '\b':
			fputs("\\b", file);
			break;
		case '\f':
			fputs("\\f", file);
			break;
		case '\n':
			fputs("\\n", file);
			break;
		case '\r':
			fputs("\\r", file);
			break;
		case '\t':
			fputs("\\t", file);
			break;
		default:
			if (*cursor < 0x20)
			{
				fprintf(file, "\\u%04x", (unsigned int)*cursor);
			}
			else
			{
				fputc((int)*cursor, file);
			}
			break;
		}
		cursor++;
	}
	fputc('"', file);

	free(utf8_text);
}

static const char* cave_type_label(uint32_t cave_type)
{
	switch (cave_type)
	{
	case CAVE_TYPE_ZERO_FILL:
		return "ZERO_FILL";
	case CAVE_TYPE_PATTERN_FILL:
		return "PATTERN_FILL";
	case CAVE_TYPE_SECTION_GAP:
		return "SECTION_GAP";
	case CAVE_TYPE_OVERLAY:
		return "OVERLAY";
	default:
		return "UNKNOWN";
	}
}

static const char* severity_label(uint32_t severity)
{
	switch (severity)
	{
	case ANOMALY_SEVERITY_LOW:
		return "LOW";
	case ANOMALY_SEVERITY_MEDIUM:
		return "MEDIUM";
	case ANOMALY_SEVERITY_HIGH:
		return "HIGH";
	case ANOMALY_SEVERITY_CRITICAL:
		return "CRITICAL";
	default:
		return "UNKNOWN";
	}
}

static const char* risk_category(double suspicion)
{
	if (suspicion >= REPORT_HIGH_RISK_THRESHOLD)
	{
		return "high";
	}
	if (suspicion >= 0.30)
	{
		return "medium";
	}
	return "low";
}

static const char* anomaly_risk_category(uint32_t severity)
{
	if (severity >= ANOMALY_SEVERITY_HIGH)
	{
		return "high";
	}
	if (severity >= ANOMALY_SEVERITY_MEDIUM)
	{
		return "medium";
	}
	return "low";
}

static const char* html_risk_grade_label(const char* risk_grade)
{
	if (!risk_grade)
	{
		return "&#26410;&#30693;";
	}
	if (strcmp(risk_grade, "CRITICAL") == 0)
	{
		return "&#20005;&#37325;";
	}
	if (strcmp(risk_grade, "HIGH") == 0)
	{
		return "&#39640;&#21361;";
	}
	if (strcmp(risk_grade, "ELEVATED") == 0)
	{
		return "&#36739;&#39640;";
	}
	if (strcmp(risk_grade, "GUARDED") == 0)
	{
		return "&#20851;&#27880;";
	}
	if (strcmp(risk_grade, "LOW") == 0)
	{
		return "&#20302;&#39118;&#38505;";
	}
	return "&#26410;&#30693;";
}

static const char* html_severity_label(uint32_t severity)
{
	switch (severity)
	{
	case ANOMALY_SEVERITY_LOW:
		return "&#20302;";
	case ANOMALY_SEVERITY_MEDIUM:
		return "&#20013;";
	case ANOMALY_SEVERITY_HIGH:
		return "&#39640;";
	case ANOMALY_SEVERITY_CRITICAL:
		return "&#20005;&#37325;";
	default:
		return "&#26410;&#30693;";
	}
}

static const char* html_cave_type_label(uint32_t cave_type)
{
	switch (cave_type)
	{
	case CAVE_TYPE_ZERO_FILL:
		return "&#38646;&#22635;&#20805;";
	case CAVE_TYPE_PATTERN_FILL:
		return "&#27169;&#24335;&#22635;&#20805;";
	case CAVE_TYPE_SECTION_GAP:
		return "&#33410;&#21306;&#38388;&#38553;";
	case CAVE_TYPE_OVERLAY:
		return "&#35206;&#30422;&#23618;";
	default:
		return "&#26410;&#30693;";
	}
}

static double clamp_double(double value, double minimum, double maximum)
{
	if (value < minimum)
	{
		return minimum;
	}
	if (value > maximum)
	{
		return maximum;
	}
	return value;
}

static uint32_t clamp_u32(uint32_t value, uint32_t maximum)
{
	return value > maximum ? maximum : value;
}

static void format_file_size(uint32_t bytes, char* output, size_t output_size)
{
	if (bytes >= 1024u * 1024u)
	{
		snprintf(output, output_size, "%.2f MB", (double)bytes / (1024.0 * 1024.0));
	}
	else if (bytes >= 1024u)
	{
		snprintf(output, output_size, "%.2f KB", (double)bytes / 1024.0);
	}
	else
	{
		snprintf(output, output_size, "%u B", bytes);
	}
}

static void format_time_strings(
	time_t value,
	char* iso_output,
	size_t iso_size,
	char* display_output,
	size_t display_size,
	char* file_output,
	size_t file_size)
{
	struct tm local_time;

	if (iso_output && iso_size)
	{
		iso_output[0] = '\0';
	}
	if (display_output && display_size)
	{
		display_output[0] = '\0';
	}
	if (file_output && file_size)
	{
		file_output[0] = '\0';
	}

	if (localtime_s(&local_time, &value) != 0)
	{
		return;
	}

	if (iso_output && iso_size)
	{
		strftime(iso_output, iso_size, "%Y-%m-%dT%H:%M:%S", &local_time);
	}
	if (display_output && display_size)
	{
		strftime(display_output, display_size, "%Y-%m-%d %H:%M:%S", &local_time);
	}
	if (file_output && file_size)
	{
		strftime(file_output, file_size, "%Y%m%d_%H%M%S", &local_time);
	}
}

static void make_report_stem(const char* target_path, char* output, size_t output_size)
{
	const char* basename;
	const char* cursor;
	const char* last_dot;
	size_t input_length;
	size_t output_length = 0;

	if (!output || output_size == 0)
	{
		return;
	}
	output[0] = '\0';

	if (!target_path)
	{
		snprintf(output, output_size, "pe_report");
		return;
	}

	basename = target_path;
	for (cursor = target_path; *cursor; cursor++)
	{
		if (*cursor == '\\' || *cursor == '/')
		{
			basename = cursor + 1;
		}
	}

	input_length = bounded_length(basename, MAX_PATH);
	if (input_length == 0)
	{
		snprintf(output, output_size, "pe_report");
		return;
	}

	last_dot = strrchr(basename, '.');
	if (last_dot && last_dot > basename)
	{
		input_length = (size_t)(last_dot - basename);
	}

	for (size_t i = 0; i < input_length && output_length + 1 < output_size; i++)
	{
		unsigned char c = (unsigned char)basename[i];
		if (isalnum(c) || c == '-' || c == '_')
		{
			output[output_length++] = (char)c;
		}
		else
		{
			output[output_length++] = '_';
		}
	}

	if (output_length == 0)
	{
		snprintf(output, output_size, "pe_report");
		return;
	}

	output[output_length] = '\0';
}

static BOOL directory_exists(const char* path)
{
	DWORD attributes;

	if (!path || path[0] == '\0')
	{
		return TRUE;
	}

	attributes = GetFileAttributesA(path);
	return attributes != INVALID_FILE_ATTRIBUTES
		&& (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static BOOL ensure_directory_tree(const char* path)
{
	char working[MAX_PATH];
	size_t length;

	if (!path || path[0] == '\0' || strcmp(path, ".") == 0)
	{
		return TRUE;
	}

	length = bounded_length(path, MAX_PATH - 1);
	if (length == 0 || length >= MAX_PATH)
	{
		return FALSE;
	}

	memcpy(working, path, length + 1);
	while (length > 0
		&& (working[length - 1] == '\\' || working[length - 1] == '/')
		&& !(length == 3 && working[1] == ':'))
	{
		working[--length] = '\0';
	}

	if (directory_exists(working))
	{
		return TRUE;
	}

	for (size_t i = 1; i < length; i++)
	{
		if (working[i] == '\\' || working[i] == '/')
		{
			char separator = working[i];
			working[i] = '\0';

			if (working[0] != '\0'
				&& !(strlen(working) == 2 && working[1] == ':')
				&& !directory_exists(working))
			{
				if (!CreateDirectoryA(working, NULL)
					&& GetLastError() != ERROR_ALREADY_EXISTS)
				{
					return FALSE;
				}
			}

			working[i] = separator;
		}
	}

	if (!directory_exists(working))
	{
		if (!CreateDirectoryA(working, NULL)
			&& GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return FALSE;
		}
	}

	return TRUE;
}

static analysis_result_t build_report_path(
	const analysis_report_t* report,
	const config_t* config,
	const char* extension,
	char* output_path,
	size_t output_size,
	char* generated_at,
	size_t generated_at_size)
{
	const char* output_directory;
	char stem[96];
	char file_timestamp[32];
	char iso_timestamp[32];
	char display_timestamp[32];
	size_t directory_length;
	int written;
	time_t generated_time = report->analysis_time > 0 ? report->analysis_time : time(NULL);

	if (!report || !config || !extension || !output_path || output_size == 0)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	output_directory = config->output_directory;
	if (!output_directory || output_directory[0] == '\0')
	{
		output_directory = ".";
	}

	if (!ensure_directory_tree(output_directory))
	{
		return RESULT_ERROR_ANALYSIS_FAILED;
	}

	format_time_strings(
		generated_time,
		iso_timestamp,
		sizeof(iso_timestamp),
		display_timestamp,
		sizeof(display_timestamp),
		file_timestamp,
		sizeof(file_timestamp));

	if (generated_at && generated_at_size)
	{
		snprintf(generated_at, generated_at_size, "%s", iso_timestamp);
	}

	make_report_stem(report->target_file, stem, sizeof(stem));
	directory_length = bounded_length(output_directory, MAX_PATH);

	if (directory_length > 0
		&& (output_directory[directory_length - 1] == '\\'
			|| output_directory[directory_length - 1] == '/'))
	{
		written = snprintf(
			output_path,
			output_size,
			"%s%s_PE_CodeCave_%s.%s",
			output_directory,
			stem,
			file_timestamp,
			extension);
	}
	else
	{
		written = snprintf(
			output_path,
			output_size,
			"%s\\%s_PE_CodeCave_%s.%s",
			output_directory,
			stem,
			file_timestamp,
			extension);
	}

	if (written < 0 || (size_t)written >= output_size)
	{
		output_path[0] = '\0';
		return RESULT_ERROR_ANALYSIS_FAILED;
	}

	return RESULT_SUCCESS;
}

static void collect_report_stats(const analysis_report_t* report, report_stats_t* stats)
{
	uint32_t cave_count;
	uint32_t anomaly_count;
	uint32_t section_count;
	double suspicion_total = 0.0;
	double severity_weight = 0.0;

	memset(stats, 0, sizeof(*stats));

	cave_count = clamp_u32(report->total_cave_found, MAX_CAVES_PER_FILE);
	anomaly_count = clamp_u32(report->anomalies_detected, MAX_ANMALIES_PER_FILE);
	section_count = report->pe_info.section
		? (uint32_t)report->pe_info.section_count
		: 0u;

	stats->cave_count = cave_count;
	stats->anomaly_count = anomaly_count;

	for (uint32_t i = 0; i < cave_count; i++)
	{
		const code_cave_t* cave = &report->cave[i];
		double suspicion = clamp_double(cave->suspicion_level, 0.0, 1.0);

		suspicion_total += suspicion;
		if (suspicion > stats->max_suspicion)
		{
			stats->max_suspicion = suspicion;
		}
		if (suspicion >= REPORT_HIGH_RISK_THRESHOLD)
		{
			stats->high_risk_caves++;
		}

		stats->total_cave_bytes += cave->size;
		switch (cave->cave_type)
		{
		case CAVE_TYPE_ZERO_FILL:
			stats->zero_fill_caves++;
			break;
		case CAVE_TYPE_PATTERN_FILL:
			stats->pattern_fill_caves++;
			break;
		case CAVE_TYPE_SECTION_GAP:
			stats->gap_caves++;
			break;
		case CAVE_TYPE_OVERLAY:
			stats->overlay_caves++;
			break;
		default:
			break;
		}
	}

	if (cave_count > 0)
	{
		stats->average_suspicion = suspicion_total / (double)cave_count;
	}
	if (report->hign_risk_cave > stats->high_risk_caves)
	{
		stats->high_risk_caves = clamp_u32(report->hign_risk_cave, cave_count);
	}

	for (uint32_t i = 0; i < anomaly_count; i++)
	{
		uint32_t severity = clamp_u32(report->anomalies[i].severity, 4);
		stats->severity_counts[severity]++;
		switch (severity)
		{
		case ANOMALY_SEVERITY_LOW:
			severity_weight += 1.5;
			break;
		case ANOMALY_SEVERITY_MEDIUM:
			severity_weight += 3.0;
			break;
		case ANOMALY_SEVERITY_HIGH:
			severity_weight += 5.0;
			break;
		case ANOMALY_SEVERITY_CRITICAL:
			severity_weight += 8.0;
			break;
		default:
			break;
		}
	}

	for (uint32_t i = 0; i < section_count; i++)
	{
		const section_info_t* section = &report->pe_info.section[i];

		if (section->is_executable)
		{
			stats->executable_sections++;
		}
		if (section->is_executable && section->is_writable)
		{
			stats->rwx_sections++;
		}
	}

	stats->cave_component =
		clamp_double((double)cave_count * 1.25, 0.0, 20.0)
		+ stats->max_suspicion * 20.0
		+ stats->average_suspicion * 10.0
		+ clamp_double((double)stats->high_risk_caves * 3.0, 0.0, 15.0);

	stats->anomaly_component =
		clamp_double(severity_weight, 0.0, 25.0)
		+ clamp_double((double)anomaly_count, 0.0, 5.0);

	stats->section_component =
		clamp_double((double)stats->rwx_sections * 6.0, 0.0, 12.0);

	for (uint32_t i = 0; i < section_count; i++)
	{
		const section_info_t* section = &report->pe_info.section[i];
		if (!section->is_executable)
		{
			continue;
		}
		if (section->entropy < LOW_ENTROPY_THRESHOLD)
		{
			stats->section_component += 2.0;
		}
		if (section->entropy > HIGN_ENTROPY_THRESHOLD)
		{
			stats->section_component += 2.0;
		}
	}
	stats->section_component = clamp_double(stats->section_component, 0.0, 20.0);

	stats->risk_score = (int)clamp_double(
		stats->cave_component + stats->anomaly_component + stats->section_component + 0.5,
		0.0,
		100.0);

	if (stats->risk_score >= 80)
	{
		stats->risk_grade = "CRITICAL";
		stats->risk_class = "critical";
	}
	else if (stats->risk_score >= 60)
	{
		stats->risk_grade = "HIGH";
		stats->risk_class = "high";
	}
	else if (stats->risk_score >= 35)
	{
		stats->risk_grade = "ELEVATED";
		stats->risk_class = "medium";
	}
	else if (stats->risk_score >= 15)
	{
		stats->risk_grade = "GUARDED";
		stats->risk_class = "low";
	}
	else
	{
		stats->risk_grade = "LOW";
		stats->risk_class = "low";
	}
}

static void write_html_document_head(FILE* file)
{
	fputs(
		"<!doctype html>\n"
		"<html lang=\"zh-CN\">\n"
		"<head>\n"
		"<meta charset=\"utf-8\">\n"
		"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
		"<meta name=\"color-scheme\" content=\"dark\">\n"
		"<link rel=\"icon\" href=\"data:,\">\n"
		"<title>PE CodeCave | &#25915;&#20987;&#38754;&#20998;&#26512;&#25253;&#21578;</title>\n"
		"<style>\n"
		":root{--bg:#0b0f12;--surface:#11171c;--surface-2:#151d23;--line:#26333d;"
		"--text:#e8eef2;--muted:#8ea0ac;--teal:#2dd4bf;--orange:#ff9f43;"
		"--red:#ff637d;--yellow:#f6c85f;--blue:#76a9ff;--green:#57d68d;"
		"--radius:8px;--mono:ui-monospace,SFMono-Regular,Consolas,'Liberation Mono',monospace;"
		"--sans:Inter,Segoe UI,Microsoft YaHei,sans-serif}\n"
		"*{box-sizing:border-box}html{background:var(--bg);color:var(--text);"
		"font-family:var(--sans)}body{margin:0;min-height:100vh;background:var(--bg)}"
		"button,input{font:inherit}.shell{width:min(1480px,100%);margin:0 auto;padding:22px 28px 34px}"
		".topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;"
		"padding:14px 16px;border:1px solid var(--line);background:var(--surface);border-radius:var(--radius)}"
		".brand{display:flex;align-items:center;gap:12px;min-width:0}.brand-mark{display:grid;"
		"place-items:center;width:42px;height:42px;border-radius:6px;background:#15262a;"
		"border:1px solid #2b5258;color:var(--teal);font:700 15px var(--mono)}"
		".brand strong{display:block;font:700 20px/1.1 var(--mono)}.brand small{display:block;"
		"margin-top:4px;color:var(--muted);font-size:12px}.top-actions{display:flex;"
		"align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end}.status{display:inline-flex;"
		"align-items:center;gap:8px;min-height:34px;padding:0 11px;border:1px solid #245541;"
		"background:#102019;color:#88e0ad;border-radius:6px;font:700 11px var(--mono)}"
		".status:before{content:'';width:7px;height:7px;border-radius:50%;background:var(--green);"
		"box-shadow:0 0 0 4px rgba(87,214,141,.12)}.print{border:1px solid #3b4b56;background:#182128;"
		"color:var(--text);min-height:34px;padding:0 13px;border-radius:6px;cursor:pointer}"
		".print:hover{border-color:#647986}.report-head{display:flex;align-items:flex-end;"
		"justify-content:space-between;gap:26px;padding:34px 2px 24px;border-bottom:1px solid var(--line)}"
		".eyebrow{margin:0 0 9px;color:var(--teal);font:700 11px var(--mono)}"
		"h1{margin:0;font-size:clamp(28px,4vw,44px);line-height:1.05;color:#f3f7f9}"
		".target-line{margin:13px 0 0;color:var(--muted);font-size:13px}.target-line code{display:inline-block;"
		"max-width:min(720px,78vw);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"
		"vertical-align:bottom;color:#d5e3ea;font:12px var(--mono)}.report-meta{display:grid;gap:6px;"
		"min-width:230px;text-align:right;color:var(--muted);font:11px var(--mono)}"
		".report-meta strong{color:#dce7ed;font-size:12px}.overview-grid{display:grid;"
		"grid-template-columns:minmax(280px,.85fr) minmax(0,2.15fr);gap:16px;margin-top:18px}"
		".score-panel{display:grid;grid-template-columns:170px minmax(0,1fr);align-items:center;gap:14px;"
		"padding:20px;border:1px solid var(--line);background:var(--surface);border-radius:var(--radius)}"
		".gauge{position:relative;width:160px;height:160px}.gauge svg{width:160px;height:160px;"
		"transform:rotate(-90deg)}.gauge-track{fill:none;stroke:#22303a;stroke-width:11}"
		".gauge-value{fill:none;stroke:var(--orange);stroke-width:11;stroke-linecap:round}"
		".gauge-center{position:absolute;inset:0;display:grid;place-content:center;text-align:center}"
		".gauge-score{font:800 37px/1 var(--mono);color:#fff}.gauge-label{margin-top:6px;"
		"color:var(--muted);font:700 9px var(--mono)}.score-copy h2{margin:0 0 6px;font-size:15px}"
		".risk-grade{display:inline-flex;align-items:center;min-height:28px;padding:0 9px;border-radius:5px;"
		"border:1px solid #48545c;background:#1b2329;font:800 11px var(--mono);margin:5px 0 13px}"
		".risk-grade.critical,.risk-grade.high{color:#ff9aaa;border-color:#653640;background:#28161c}"
		".risk-grade.medium{color:#f7d77b;border-color:#665327;background:#252114}"
		".risk-grade.low{color:#83e5b3;border-color:#2b5a43;background:#14251c}"
		".score-copy p{margin:0;color:var(--muted);font-size:12px;line-height:1.6}"
		".kpi-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}"
		".kpi{min-height:104px;padding:15px;border:1px solid var(--line);background:var(--surface);"
		"border-radius:var(--radius);display:flex;flex-direction:column;justify-content:space-between}"
		".kpi-label{color:var(--muted);font:700 10px var(--mono);text-transform:uppercase}"
		".kpi-value{font:800 30px/1 var(--mono);color:#fff}.kpi-value small{font-size:12px;color:var(--muted)}"
		".kpi-note{color:#728793;font-size:11px}.panel{margin-top:16px;border:1px solid var(--line);"
		"background:var(--surface);border-radius:var(--radius);overflow:hidden}.panel-head{display:flex;"
		"align-items:center;justify-content:space-between;gap:18px;padding:16px 18px;border-bottom:1px solid var(--line)}"
		".panel-head h2{margin:0;font-size:15px}.panel-head .hint{color:#748792;font:10px var(--mono)}"
		".entropy-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;padding:16px}"
		".entropy-item{padding:14px;border:1px solid #24313a;background:var(--surface-2);border-radius:6px}"
		".section-top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:11px}"
		".section-name{font:700 13px var(--mono);color:#eaf0f3;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
		".section-flags{display:flex;gap:5px;flex-shrink:0}.flag{min-width:22px;height:21px;padding:0 5px;"
		"display:grid;place-items:center;border:1px solid #34434d;border-radius:4px;color:#8799a4;"
		"font:700 9px var(--mono)}.flag.x{color:#7fc7ff;border-color:#31526b}.flag.w{color:#ffbd70;"
		"border-color:#624826}.bar-track{height:8px;background:#1f2a32;border-radius:4px;overflow:hidden}"
		".bar-fill{height:100%;background:var(--teal);border-radius:4px}.bar-fill.hot{background:var(--red)}"
		".section-meta{display:flex;justify-content:space-between;gap:12px;margin-top:8px;color:var(--muted);"
		"font:10px var(--mono)}.toolbar{display:flex;align-items:center;gap:9px;flex-wrap:wrap}"
		".search{min-height:34px;width:min(260px,100%);padding:0 11px;border:1px solid #34434d;"
		"background:#0f1519;color:var(--text);border-radius:6px;outline:none}.search:focus{border-color:var(--teal)}"
		".segment{display:flex;border:1px solid #34434d;border-radius:6px;overflow:hidden}.segment button{"
		"min-height:32px;padding:0 10px;border:0;border-right:1px solid #34434d;background:#121a1f;"
		"color:var(--muted);cursor:pointer;font:700 10px var(--mono)}.segment button:last-child{border-right:0}"
		".segment button.active{background:#223039;color:#fff}.table-wrap{overflow:auto}table{width:100%;"
		"border-collapse:collapse;min-width:760px}th,td{padding:12px 14px;border-bottom:1px solid #202c34;"
		"text-align:left;white-space:nowrap}th{position:sticky;top:0;background:#10171c;color:#748792;"
		"font:700 9px var(--mono);text-transform:uppercase}td{font-size:12px}tr:last-child td{border-bottom:0}"
		"tbody tr:hover{background:#151f25}.mono{font-family:var(--mono)}.muted{color:var(--muted)}"
		".pill{display:inline-flex;align-items:center;min-height:23px;padding:0 7px;border-radius:4px;"
		"border:1px solid #3d4d57;background:#19242b;font:700 9px var(--mono)}"
		".pill.high,.pill.critical{color:#ff9aaa;border-color:#683843;background:#28171d}"
		".pill.medium{color:#f7d77b;border-color:#665327;background:#252114}"
		".pill.low{color:#83e5b3;border-color:#2b5a43;background:#14251c}.empty{padding:34px 18px;"
		"text-align:center;color:var(--muted);font:12px var(--mono)}.split-grid{display:grid;"
		"grid-template-columns:minmax(0,1.55fr) minmax(300px,.75fr);gap:16px;margin-top:16px}"
		".split-grid .panel{margin-top:0}.advisory{padding:16px}.advisory h3{margin:0 0 9px;font-size:13px}"
		".advisory p{margin:0 0 14px;color:var(--muted);font-size:12px;line-height:1.7}"
		".advisory ul{display:grid;gap:9px;margin:0;padding:0;list-style:none}.advisory li{position:relative;"
		"padding:11px 12px 11px 28px;border:1px solid #26343d;background:var(--surface-2);border-radius:6px;"
		"color:#c7d4dc;font-size:12px;line-height:1.55}.advisory li:before{content:'//';position:absolute;"
		"left:10px;top:11px;color:var(--orange);font:700 9px var(--mono)}.triage{display:grid;"
		"grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin:14px 0 0}.triage div{padding:10px;"
		"border:1px solid #26343d;background:#10171b;border-radius:5px}.triage span{display:block;color:#748792;"
		"font:9px var(--mono)}.triage strong{display:block;margin-top:4px;font:700 12px var(--mono);color:#dce7ed}"
		"footer{display:flex;justify-content:space-between;gap:20px;padding:18px 2px 0;color:#637782;"
		"font:10px var(--mono)}.hidden{display:none!important}"
		"@media(max-width:1080px){.overview-grid{grid-template-columns:1fr}.split-grid{grid-template-columns:1fr}"
		".kpi-grid{grid-template-columns:repeat(3,minmax(0,1fr))}}"
		"@media(max-width:760px){.shell{padding:12px 12px 24px}.topbar,.report-head,.panel-head{"
		"align-items:flex-start;flex-direction:column}.report-meta{text-align:left}.overview-grid{"
		"margin-top:12px}.score-panel{grid-template-columns:140px minmax(0,1fr);padding:14px}"
		".gauge,.gauge svg{width:136px;height:136px}.kpi-grid{grid-template-columns:repeat(2,minmax(0,1fr))}"
		".entropy-grid{grid-template-columns:1fr}.target-line code{max-width:100%}footer{flex-direction:column}"
		"table{min-width:0}th,td{white-space:normal}.cave-table th:nth-child(1),.cave-table td:nth-child(1),"
		".cave-table th:nth-child(7),.cave-table td:nth-child(7),.anomaly-table th:nth-child(4),"
		".anomaly-table td:nth-child(4),.anomaly-table th:nth-child(5),.anomaly-table td:nth-child(5){display:none}}"
		"@media(max-width:480px){.score-panel{grid-template-columns:1fr}.gauge{margin:0 auto}"
		".kpi-grid{grid-template-columns:1fr}.toolbar{align-items:stretch}.search{width:100%}"
		".segment{overflow:auto}.brand strong{font-size:17px}.cave-table th:nth-child(5),"
		".cave-table td:nth-child(5){display:none}}"
		"@media print{html{background:#fff;color:#111}body{background:#fff}.shell{max-width:none;padding:0}"
		".topbar,.panel,.kpi,.score-panel{border-color:#bbb;background:#fff;box-shadow:none}"
		".print,.segment,.search{display:none!important}.report-head{border-color:#bbb}.target-line code,"
		".muted,.kpi-label,.kpi-note,.section-meta,footer{color:#555}h1,.gauge-score,.kpi-value,"
		".brand strong,td,.section-name{color:#111}.panel-head,th,td,.topbar{border-color:#ccc}"
		".entropy-item,.advisory li,.triage div{background:#f6f6f6;border-color:#ddd}}"
		"</style>\n"
		"</head>\n"
		"<body>\n",
		file);
}

static void write_recommendation_item(
	FILE* file,
	const char* text,
	BOOL* any_written)
{
	fprintf(file, "<li>%s</li>", text);
	*any_written = TRUE;
}

static void write_html_report(FILE* file, const analysis_report_t* report, const report_stats_t* stats)
{
	char display_generated_at[32];
	char display_analysis_at[32];
	char file_size_text[32];
	const double circumference = 339.2920066;
	double gauge_length;
	uint32_t section_count = report->pe_info.section ? report->pe_info.section_count : 0u;
	BOOL recommendation_written = FALSE;

	format_time_strings(
		time(NULL),
		NULL,
		0,
		display_generated_at,
		sizeof(display_generated_at),
		NULL,
		0);

	if (report->analysis_time > 0)
	{
		format_time_strings(
			report->analysis_time,
			NULL,
			0,
			display_analysis_at,
			sizeof(display_analysis_at),
			NULL,
			0);
	}
	else
	{
		snprintf(display_analysis_at, sizeof(display_analysis_at), "%s", display_generated_at);
	}

	gauge_length = circumference * ((double)stats->risk_score / 100.0);
	format_file_size(report->pe_info.file_size, file_size_text, sizeof(file_size_text));

	write_html_document_head(file);

	fputs("<div class=\"shell\">\n", file);
	fputs("<header class=\"topbar\">", file);
	fputs(
		"<div class=\"brand\"><span class=\"brand-mark\">PC</span><div>"
		"<strong>PE CodeCave</strong><small>&#20108;&#36827;&#21046;&#25915;&#20987;&#38754;&#24773;&#25253;</small></div></div>",
		file);
	fputs(
		"<div class=\"top-actions\"><span class=\"status\">"
		"&#38745;&#24577;&#20998;&#26512;&#23436;&#25104;</span>"
		"<button class=\"print\" type=\"button\" onclick=\"window.print()\">"
		"&#25171;&#21360; / &#23548;&#20986; PDF</button></div>",
		file);
	fputs("</header>\n<main>\n", file);

	fputs("<section class=\"report-head\">", file);
	fputs("<div><p class=\"eyebrow\">&#23433;&#20840;&#35780;&#20272; / ", file);
	fputs(HTML_LBL_SECURITY_REPORT, file);
	fputs(
		"</p><h1>&#25915;&#20987;&#38754;&#20998;&#26512;&#25253;&#21578;</h1>"
		"<p class=\"target-line\">",
		file);
	fputs(HTML_LBL_TARGET_FILE, file);
	fputs(" &nbsp; <code title=\"", file);
	write_html_text(file, report->target_file, MAX_PATH);
	fputs("\">", file);
	write_html_text(file, report->target_file, MAX_PATH);
	fputs("</code></p></div>", file);
	fputs(
		"<div class=\"report-meta\"><span>&#20998;&#26512;&#24341;&#25806; "
		"<strong>PE CodeCave / C</strong></span>"
		"<span>&#25253;&#21578;&#26550;&#26500; "
		"<strong>pe-codecave.report.v1</strong></span>",
		file);
	fputs("<span>", file);
	fputs(HTML_LBL_GENERATED_AT, file);
	fputs(" <strong>", file);
	write_html_text(file, display_generated_at, sizeof(display_generated_at));
	fputs("</strong></span></div></section>\n", file);

	fputs("<section class=\"overview-grid\">\n", file);
	fputs("<article class=\"score-panel\">\n", file);
	fputs(
		"<div class=\"gauge\" aria-label=\"&#39118;&#38505;&#35780;&#20998;\">"
		"<svg viewBox=\"0 0 160 160\" role=\"img\">",
		file);
	fputs(
		"<circle class=\"gauge-track\" cx=\"80\" cy=\"80\" r=\"54\"></circle>"
		"<circle class=\"gauge-value\" cx=\"80\" cy=\"80\" r=\"54\" ",
		file);
	fprintf(
		file,
		"stroke-dasharray=\"%.3f %.3f\" stroke-dashoffset=\"0\"></circle></svg>",
		gauge_length,
		circumference - gauge_length);
	fputs("<div class=\"gauge-center\"><span class=\"gauge-score\">", file);
	fprintf(file, "%d", stats->risk_score);
	fputs(
		"</span><span class=\"gauge-label\">&#39118;&#38505; / 100</span>"
		"</div></div>",
		file);
	fputs("<div class=\"score-copy\"><h2>", file);
	fputs(HTML_LBL_RISK_SCORE, file);
	fputs("</h2><div class=\"risk-grade ", file);
	fputs(stats->risk_class, file);
	fputs("\">", file);
	fputs(html_risk_grade_label(stats->risk_grade), file);
	fputs(
		"</div><p>&#32508;&#21512;&#39118;&#38505;&#35780;&#20998;&#30001;&#20195;&#30721;"
		"&#27934;&#31348;&#32622;&#20449;&#24230;&#12289;&#24322;&#24120;&#20005;&#37325;"
		"&#31243;&#24230;&#21644; PE &#33410;&#21306;&#23433;&#20840;&#24577;&#21183;"
		"&#35745;&#31639;&#24471;&#20986;&#12290;&#35813;&#35780;&#20998;&#20165;"
		"&#29992;&#20110;&#30740;&#21028;&#65292;&#19981;&#20195;&#34920;&#26368;"
		"&#32456;&#24694;&#24847;&#36719;&#20214;&#32467;&#35770;&#12290;</p>"
		"</div></article>\n",
		file);

	fputs("<div class=\"kpi-grid\">\n", file);
	fputs("<div class=\"kpi\"><span class=\"kpi-label\">", file);
	fputs(HTML_LBL_CODE_CAVES, file);
	fputs("</span><span class=\"kpi-value\">", file);
	fprintf(file, "%u", stats->cave_count);
	fputs("</span><span class=\"kpi-note\">", file);
	fprintf(
		file,
		"%u &#23383;&#33410;&#20505;&#36873;&#31354;&#38386;&#31354;&#38388;",
		stats->total_cave_bytes);
	fputs("</span></div>", file);

	fputs("<div class=\"kpi\"><span class=\"kpi-label\">", file);
	fputs(HTML_LBL_HIGH_RISK_CAVES, file);
	fputs("</span><span class=\"kpi-value\">", file);
	fprintf(file, "%u", stats->high_risk_caves);
	fputs(
		"</span><span class=\"kpi-note\">&#32622;&#20449;&#24230; &ge; 60%"
		"</span></div>",
		file);

	fputs("<div class=\"kpi\"><span class=\"kpi-label\">", file);
	fputs(HTML_LBL_ANOMALIES, file);
	fputs("</span><span class=\"kpi-value\">", file);
	fprintf(file, "%u", stats->anomaly_count);
	fputs("</span><span class=\"kpi-note\">",
		file);
	fprintf(
		file,
		"%u &#39640;&#21361; / %u &#20005;&#37325;",
		stats->severity_counts[ANOMALY_SEVERITY_HIGH],
		stats->severity_counts[ANOMALY_SEVERITY_CRITICAL]);
	fputs("</span></div>", file);

	fputs("<div class=\"kpi\"><span class=\"kpi-label\">", file);
	fputs(HTML_LBL_SECTIONS, file);
	fputs("</span><span class=\"kpi-value\">", file);
	fprintf(file, "%u", section_count);
	fputs("</span><span class=\"kpi-note\">", file);
	fprintf(
		file,
		"%u &#21487;&#25191;&#34892; / %u &#21487;&#20889;&#21487;&#25191;&#34892;",
		stats->executable_sections,
		stats->rwx_sections);
	fputs("</span></div>", file);

	fputs("<div class=\"kpi\"><span class=\"kpi-label\">", file);
	fputs(HTML_LBL_OVERALL_ENTROPY, file);
	fputs("</span><span class=\"kpi-value\">", file);
	fprintf(file, "%.3f", report->pe_info.overall_entropy);
	fputs(
		"<small> / 8</small></span><span class=\"kpi-note\">"
		"&#20840;&#25991;&#20214;&#39321;&#20892;&#29109;</span></div>",
		file);

	fputs(
		"<div class=\"kpi\"><span class=\"kpi-label\">&#25991;&#20214;&#22823;&#23567;"
		"</span><span class=\"kpi-value\">",
		file);
	fprintf(file, "%u", report->pe_info.file_size);
	fputs("<small> B</small></span><span class=\"kpi-note\">", file);
	write_html_text(file, file_size_text, sizeof(file_size_text));
	fputs("</span></div>\n</div>\n</section>\n", file);

	fputs("<section class=\"panel\"><div class=\"panel-head\"><h2>", file);
	fputs(HTML_LBL_SECTION_ENTROPY, file);
	fputs(
		"</h2><span class=\"hint\">&#29109;&#20540;&#33539;&#22260; 0.000 - 8.000"
		"</span></div><div class=\"entropy-grid\">",
		file);
	if (section_count == 0)
	{
		fputs(
			"<div class=\"empty\">&#26410;&#35299;&#26512;&#21040; PE &#33410;&#21306;&#12290;</div>",
			file);
	}
	else
	{
		for (uint32_t i = 0; i < section_count; i++)
		{
			const section_info_t* section = &report->pe_info.section[i];
			double entropy = clamp_double(section->entropy, 0.0, 8.0);
			double width = entropy / 8.0 * 100.0;

			fputs("<div class=\"entropy-item\"><div class=\"section-top\"><span class=\"section-name\" title=\"", file);
			write_html_text(file, section->name, IMAGE_SIZEOF_SHORT_NAME);
			fputs("\">", file);
			write_html_text(file, section->name, IMAGE_SIZEOF_SHORT_NAME);
			fputs("</span><span class=\"section-flags\">", file);
			if (section->is_executable)
			{
				fputs("<span class=\"flag x\">X</span>", file);
			}
			if (section->is_writable)
			{
				fputs("<span class=\"flag w\">W</span>", file);
			}
			fputs("</span></div><div class=\"bar-track\"><div class=\"bar-fill", file);
			if (section->entropy > HIGN_ENTROPY_THRESHOLD || section->entropy < LOW_ENTROPY_THRESHOLD)
			{
				fputs(" hot", file);
			}
			fprintf(file, "\" style=\"width:%.2f%%\"></div></div>", width);
			fputs("<div class=\"section-meta\"><span>&#29109;&#20540; ", file);
			fprintf(file, "%.3f", section->entropy);
			fputs("</span><span>VA ", file);
			fprintf(file, "0x%08X", section->virtual_address);
			fputs(" / RAW ", file);
			fprintf(file, "0x%08X", section->raw_address);
			fputs("</span></div></div>", file);
		}
	}
	fputs("</div></section>\n", file);

	fputs("<section class=\"panel\"><div class=\"panel-head\"><h2>", file);
	fputs(HTML_LBL_CAVE_LIST, file);
	fprintf(file, " <span class=\"muted\">(%u)</span></h2>", stats->cave_count);
	fputs(
		"<div class=\"toolbar\"><input id=\"caveSearch\" class=\"search\" type=\"search\" "
		"placeholder=\"&#25628;&#32034;&#20559;&#31227;&#12289;&#31867;&#22411;"
		"&#25110;&#33410;&#21306;...\" aria-label=\"&#25628;&#32034;&#20195;&#30721;"
		"&#27934;&#31348;\">"
		"<div class=\"segment\" id=\"caveFilters\">"
		"<button type=\"button\" class=\"active\" data-cave-filter=\"all\">"
		"&#20840;&#37096;</button>"
		"<button type=\"button\" data-cave-filter=\"high\">&#39640;&#21361;</button>"
		"<button type=\"button\" data-cave-filter=\"medium\">&#20013;&#21361;</button>"
		"<button type=\"button\" data-cave-filter=\"low\">&#20302;&#21361;</button>"
		"</div></div></div>",
		file);
	fputs(
		"<div class=\"table-wrap\"><table class=\"cave-table\"><thead><tr>"
		"<th>&#24207;&#21495;</th><th>&#25991;&#20214;&#20559;&#31227;</th>"
		"<th>&#22823;&#23567;</th><th>&#31867;&#22411;</th>"
		"<th>&#32622;&#20449;&#24230;</th><th>&#25152;&#23646;&#33410;&#21306;</th>"
		"<th>&#25551;&#36848;</th></tr></thead><tbody id=\"caveRows\">",
		file);
	if (stats->cave_count == 0)
	{
		fputs("<tr><td colspan=\"7\" class=\"empty\">", file);
		fputs(HTML_LBL_NO_FINDINGS, file);
		fputs("</td></tr>", file);
	}
	else
	{
		for (uint32_t i = 0; i < stats->cave_count; i++)
		{
			const code_cave_t* cave = &report->cave[i];
			const char* category = risk_category(cave->suspicion_level);
			const char* section_name = "";

			if (report->pe_info.section && cave->section_index < report->pe_info.section_count)
			{
				section_name = report->pe_info.section[cave->section_index].name;
			}

			fprintf(
				file,
				"<tr data-finding-row data-risk=\"%s\"><td class=\"mono muted\">%04u</td>"
				"<td class=\"mono\">FOA 0x%08X<br>RVA 0x%08X</td><td class=\"mono\">%u</td><td>"
				"<span class=\"pill %s\">%s</span></td><td class=\"mono\">%.1f%%</td>"
				"<td class=\"mono\">",
				category,
				i + 1u,
				cave->offset,
				cave->rva,
				cave->size,
				category,
				html_cave_type_label(cave->cave_type),
				clamp_double(cave->suspicion_level, 0.0, 1.0) * 100.0);
			write_html_text(file, section_name, IMAGE_SIZEOF_SHORT_NAME);
			fputs("</td><td class=\"muted\" title=\"", file);
			write_html_text(file, cave->descriptor, sizeof(cave->descriptor));
			fputs("\">", file);
			write_html_text(file, cave->descriptor, sizeof(cave->descriptor));
			fputs("</td></tr>", file);
		}
	}
	fputs("</tbody></table></div></section>\n", file);

	fputs("<div class=\"split-grid\">\n", file);
	fputs("<section class=\"panel\"><div class=\"panel-head\"><h2>", file);
	fputs(HTML_LBL_ANOMALY_PATTERNS, file);
	fprintf(file, " <span class=\"muted\">(%u)</span></h2>", stats->anomaly_count);
	fputs(
		"<div class=\"toolbar\"><input id=\"anomalySearch\" class=\"search\" type=\"search\" "
		"placeholder=\"&#31579;&#36873;&#24322;&#24120;&#21457;&#29616;...\" "
		"aria-label=\"&#25628;&#32034;&#24322;&#24120;&#21457;&#29616;\">"
		"<div class=\"segment\" id=\"anomalyFilters\">"
		"<button type=\"button\" class=\"active\" data-anomaly-filter=\"all\">"
		"&#20840;&#37096;</button>"
		"<button type=\"button\" data-anomaly-filter=\"high\">&#39640;&#21361;</button>"
		"<button type=\"button\" data-anomaly-filter=\"medium\">&#20013;&#21361;</button>"
		"<button type=\"button\" data-anomaly-filter=\"low\">&#20302;&#21361;</button>"
		"</div></div></div>",
		file);
	fputs(
		"<div class=\"table-wrap\"><table class=\"anomaly-table\"><thead><tr>"
		"<th>&#20005;&#37325;&#32423;&#21035;</th><th>&#24322;&#24120;&#27169;&#24335;</th>"
		"<th>&#25991;&#20214;&#20559;&#31227;</th><th>&#25152;&#23646;&#33410;&#21306;</th>"
		"<th>&#35777;&#25454;&#25551;&#36848;</th></tr></thead><tbody id=\"anomalyRows\">",
		file);
	if (stats->anomaly_count == 0)
	{
		fputs("<tr><td colspan=\"5\" class=\"empty\">", file);
		fputs(HTML_LBL_NO_FINDINGS, file);
		fputs("</td></tr>", file);
	}
	else
	{
		for (uint32_t i = 0; i < stats->anomaly_count; i++)
		{
			const anomaly_pattern_t* anomaly = &report->anomalies[i];
			const char* category = anomaly_risk_category(anomaly->severity);
			const char* section_name = "";

			if (report->pe_info.section && anomaly->section_index < report->pe_info.section_count)
			{
				section_name = report->pe_info.section[anomaly->section_index].name;
			}

			fprintf(
				file,
				"<tr data-anomaly-row data-risk=\"%s\"><td><span class=\"pill %s\">%s</span></td>"
				"<td>",
				category,
				category,
				html_severity_label(anomaly->severity));
			write_html_text(file, anomaly->pattern_name, sizeof(anomaly->pattern_name));
			fprintf(file, "</td><td class=\"mono\">0x%08X</td><td class=\"mono\">", anomaly->detected_offset);
			write_html_text(file, section_name, IMAGE_SIZEOF_SHORT_NAME);
			fputs("</td><td class=\"muted\">", file);
			write_html_text(file, anomaly->descriptor, sizeof(anomaly->descriptor));
			fputs("</td></tr>", file);
		}
	}
	fputs("</tbody></table></div></section>\n", file);

	fputs("<aside class=\"panel\"><div class=\"panel-head\"><h2>", file);
	fputs(HTML_LBL_RECOMMENDATIONS, file);
	fputs(
		"</h2><span class=\"hint\">&#22788;&#32622;&#25163;&#20876;"
		"</span></div><div class=\"advisory\">",
		file);
	fputs("<h3>", file);
	fputs(HTML_LBL_CONCLUSION, file);
	fprintf(
		file,
		"</h3><p>&#39118;&#38505;&#31561;&#32423; <strong>%s</strong>&#65292;"
		"&#32508;&#21512;&#35780;&#20998; <strong>%d/100</strong>&#12290;"
		"&#35831;&#32467;&#21512;&#25991;&#20214;&#26469;&#28304;&#12289;"
		"&#25968;&#23383;&#31614;&#21517;&#29366;&#24577;&#21644;&#27801;"
		"&#31665;&#36965;&#27979;&#20449;&#24687;&#36827;&#19968;&#27493;"
		"&#30830;&#35748;&#12290;</p>",
		html_risk_grade_label(stats->risk_grade),
		stats->risk_score);
	fputs("<ul>", file);

	if (stats->high_risk_caves > 0)
	{
		write_recommendation_item(
			file,
			"&#20248;&#20808;&#23545;&#39640;&#32622;&#20449;&#24230;&#20195;"
			"&#30721;&#27934;&#31348;&#36827;&#34892;&#21453;&#27719;&#32534;"
			"&#65292;&#24182;&#30830;&#35748;&#26159;&#21542;&#21487;&#20197;"
			"&#20174;&#30495;&#23454;&#20195;&#30721;&#36335;&#24452;&#21040;"
			"&#36798;&#12290;",
			&recommendation_written);
	}
	if (stats->rwx_sections > 0)
	{
		write_recommendation_item(
			file,
			"&#37325;&#28857;&#26816;&#26597;&#21516;&#26102;&#20855;&#22791;"
			"&#21487;&#20889;&#19982;&#21487;&#25191;&#34892;&#26435;&#38480;"
			"&#30340;&#33410;&#21306;&#65292;&#36825;&#31181;&#26435;&#38480;"
			"&#32452;&#21512;&#38656;&#35201;&#31435;&#21363;&#39564;&#35777;"
			"&#12290;",
			&recommendation_written);
	}
	if (stats->anomaly_count > 0)
	{
		write_recommendation_item(
			file,
			"&#23558;&#24322;&#24120;&#20559;&#31227;&#26144;&#23556;&#21040;"
			"&#25152;&#23646;&#20989;&#25968;&#65292;&#24182;&#19982;&#21487;"
			"&#20449;&#22522;&#32447;&#26679;&#26412;&#36827;&#34892;&#23545;"
			"&#27604;&#12290;",
			&recommendation_written);
	}
	if (report->pe_info.overall_entropy > HIGN_ENTROPY_THRESHOLD)
	{
		write_recommendation_item(
			file,
			"&#25972;&#20307;&#29109;&#20540;&#36739;&#39640;&#65292;&#21487;"
			"&#33021;&#23384;&#22312;&#21152;&#22771;&#25110;&#21152;&#23494;"
			"&#65307;&#24314;&#35758;&#26816;&#26597;&#21152;&#36733;&#22120;"
			"&#24182;&#20998;&#26512;&#35299;&#21253;&#21518;&#30340;&#20869;"
			"&#23384;&#12290;",
			&recommendation_written);
	}
	if (!recommendation_written)
	{
		write_recommendation_item(
			file,
			"&#26410;&#21457;&#29616;&#26126;&#26174;&#38745;&#24577;&#25351;"
			"&#26631;&#65292;&#24314;&#35758;&#32487;&#32493;&#25191;&#34892;"
			"&#31614;&#21517;&#12289;&#20449;&#35465;&#21644;&#36816;&#34892;"
			"&#26102;&#26816;&#26597;&#12290;",
			&recommendation_written);
	}
	fputs("</ul><div class=\"triage\">", file);
	fputs(
		"<div><span>&#20998;&#26512;&#26102;&#38388;</span><strong>",
		file);
	write_html_text(file, display_analysis_at, sizeof(display_analysis_at));
	fputs(
		"</strong></div><div><span>&#20998;&#26512;&#27169;&#22411;</span>"
		"<strong>&#20195;&#30721;&#27934;&#31348; + &#24322;&#24120;&#27169;"
		"&#24335;</strong></div>",
		file);
	fputs(
		"<div><span>&#27934;&#31348;&#23383;&#33410;&#25968;</span><strong>",
		file);
	fprintf(file, "%u", stats->total_cave_bytes);
	fputs(
		"</strong></div><div><span>&#20005;&#37325;&#32423;&#21035;</span>"
		"<strong>&#39640;&#21361;:",
		file);
	fprintf(
		file,
		"%u &#20005;&#37325;:%u</strong></div></div></div></aside>\n",
		stats->severity_counts[ANOMALY_SEVERITY_HIGH],
		stats->severity_counts[ANOMALY_SEVERITY_CRITICAL]);
	fputs("</div>\n", file);

	fputs(
		"<footer><span>PE CodeCave // &#38745;&#24577;&#20108;&#36827;"
		"&#21046;&#25915;&#20987;&#38754;&#20998;&#26512;</span><span>"
		"&#29983;&#25104;&#20110; ",
		file);
	write_html_text(file, display_generated_at, sizeof(display_generated_at));
	fputs(
		" // &#25253;&#21578;&#26550;&#26500; pe-codecave.report.v1"
		"</span></footer>\n",
		file);
	fputs("</main></div>\n", file);

	fputs(
		"<script>\n"
		"(function(){\n"
		"  function wire(searchId, filterId, rowSelector, dataName){\n"
		"    var search=document.getElementById(searchId);\n"
		"    var filters=document.getElementById(filterId);\n"
		"    if(!search||!filters)return;\n"
		"    var active='all';\n"
		"    function apply(){\n"
		"      var query=(search.value||'').trim().toLowerCase();\n"
		"      var rows=document.querySelectorAll(rowSelector);\n"
		"      for(var i=0;i<rows.length;i++){\n"
		"        var row=rows[i];\n"
		"        var risk=row.getAttribute('data-risk')||'low';\n"
		"        var matchRisk=(active==='all'||risk===active);\n"
		"        var matchQuery=(!query||(row.textContent||'').toLowerCase().indexOf(query)>=0);\n"
		"        row.classList.toggle('hidden',!(matchRisk&&matchQuery));\n"
		"      }\n"
		"    }\n"
		"    filters.addEventListener('click',function(event){\n"
		"      var button=event.target.closest('button');\n"
		"      if(!button)return;\n"
		"      active=button.getAttribute('data-'+dataName+'-filter')||'all';\n"
		"      var buttons=filters.querySelectorAll('button');\n"
		"      for(var i=0;i<buttons.length;i++)buttons[i].classList.toggle('active',buttons[i]===button);\n"
		"      apply();\n"
		"    });\n"
		"    search.addEventListener('input',apply);\n"
		"  }\n"
		"  wire('caveSearch','caveFilters','[data-finding-row]','cave');\n"
		"  wire('anomalySearch','anomalyFilters','[data-anomaly-row]','anomaly');\n"
		"})();\n"
		"</script>\n"
		"</body></html>\n",
		file);
}

static void write_json_sections(FILE* file, const analysis_report_t* report)
{
	uint32_t count = report->pe_info.section ? report->pe_info.section_count : 0u;

	fputs("\"sections\":[", file);
	for (uint32_t i = 0; i < count; i++)
	{
		const section_info_t* section = &report->pe_info.section[i];
		if (i > 0)
		{
			fputc(',', file);
		}
		fprintf(file, "{\"index\":%u,\"name\":", i);
		write_json_escaped(file, section->name, IMAGE_SIZEOF_SHORT_NAME);
		fprintf(
			file,
			",\"virtual_address\":%u,\"virtual_address_hex\":\"0x%08X\","
			"\"virtual_size\":%u,\"raw_address\":%u,\"raw_address_hex\":\"0x%08X\","
			"\"raw_size\":%u,\"characteristics\":%u,\"entropy\":%.6f,"
			"\"executable\":%s,\"writable\":%s}",
			section->virtual_address,
			section->virtual_address,
			section->virtual_size,
			section->raw_address,
			section->raw_address,
			section->raw_size,
			section->characteristics,
			section->entropy,
			section->is_executable ? "true" : "false",
			section->is_writable ? "true" : "false");
	}
	fputc(']', file);
}

static void write_json_caves(FILE* file, const analysis_report_t* report, const report_stats_t* stats)
{
	fputs("\"code_caves\":[", file);
	for (uint32_t i = 0; i < stats->cave_count; i++)
	{
		const code_cave_t* cave = &report->cave[i];
		const char* section_name = "";

		if (report->pe_info.section && cave->section_index < report->pe_info.section_count)
		{
			section_name = report->pe_info.section[cave->section_index].name;
		}

		if (i > 0)
		{
			fputc(',', file);
		}
		fprintf(
			file,
			"{\"index\":%u,\"offset\":%u,\"offset_hex\":\"0x%08X\","
			"\"rva\":%u,\"rva_hex\":\"0x%08X\",\"size\":%u,"
			"\"section_index\":%u,\"section_name\":",
			i + 1u,
			cave->offset,
			cave->offset,
			cave->rva,
			cave->rva,
			cave->size,
			cave->section_index);
		write_json_escaped(file, section_name, IMAGE_SIZEOF_SHORT_NAME);
		fputs(",\"type\":", file);
		write_json_escaped(file, cave_type_label(cave->cave_type), 32);
		fprintf(
			file,
			",\"type_code\":%u,\"suspicion\":%.6f,\"confidence_percent\":%.2f,"
			"\"risk_category\":\"%s\",\"descriptor\":",
			cave->cave_type,
			cave->suspicion_level,
			clamp_double(cave->suspicion_level, 0.0, 1.0) * 100.0,
			risk_category(cave->suspicion_level));
		write_json_escaped(file, cave->descriptor, sizeof(cave->descriptor));
		fputc('}', file);
	}
	fputc(']', file);
}

static void write_json_anomalies(FILE* file, const analysis_report_t* report, const report_stats_t* stats)
{
	fputs("\"anomalies\":[", file);
	for (uint32_t i = 0; i < stats->anomaly_count; i++)
	{
		const anomaly_pattern_t* anomaly = &report->anomalies[i];
		const char* section_name = "";

		if (report->pe_info.section && anomaly->section_index < report->pe_info.section_count)
		{
			section_name = report->pe_info.section[anomaly->section_index].name;
		}

		if (i > 0)
		{
			fputc(',', file);
		}
		fprintf(
			file,
			"{\"pattern_id\":%u,\"severity\":%u,\"severity_label\":\"%s\","
			"\"risk_category\":\"%s\",\"detected_offset\":%u,\"detected_offset_hex\":\"0x%08X\","
			"\"section_index\":%u,\"section_name\":",
			anomaly->pattern_id,
			anomaly->severity,
			severity_label(anomaly->severity),
			anomaly_risk_category(anomaly->severity),
			anomaly->detected_offset,
			anomaly->detected_offset,
			anomaly->section_index);
		write_json_escaped(file, section_name, IMAGE_SIZEOF_SHORT_NAME);
		fputs(",\"pattern_name\":", file);
		write_json_escaped(file, anomaly->pattern_name, sizeof(anomaly->pattern_name));
		fputs(",\"descriptor\":", file);
		write_json_escaped(file, anomaly->descriptor, sizeof(anomaly->descriptor));
		fputc('}', file);
	}
	fputc(']', file);
}

static void write_json_recommendations(FILE* file, const analysis_report_t* report, const report_stats_t* stats)
{
	BOOL any = FALSE;

	fputs("\"recommendations\":[", file);
	if (stats->high_risk_caves > 0)
	{
		fputs("\"Prioritize high-confidence caves for disassembly and reachability review.\"", file);
		any = TRUE;
	}
	if (stats->rwx_sections > 0)
	{
		fprintf(file, "%s\"Review writable+executable PE sections immediately.\"", any ? "," : "");
		any = TRUE;
	}
	if (stats->anomaly_count > 0)
	{
		fprintf(file, "%s\"Map anomaly offsets to owning functions and compare with a trusted baseline.\"", any ? "," : "");
		any = TRUE;
	}
	if (report->pe_info.overall_entropy > HIGN_ENTROPY_THRESHOLD)
	{
		fprintf(file, "%s\"Inspect for packing or encryption and analyze unpacked memory.\"", any ? "," : "");
		any = TRUE;
	}
	if (!any)
	{
		fputs("\"No major static indicators were found; continue with signature and runtime checks.\"", file);
	}
	fputc(']', file);
}

static void write_json_report(FILE* file, const analysis_report_t* report, const report_stats_t* stats)
{
	char generated_at[32];
	char analysis_at[32];
	uint32_t section_count = report->pe_info.section ? report->pe_info.section_count : 0u;

	format_time_strings(
		time(NULL),
		generated_at,
		sizeof(generated_at),
		NULL,
		0,
		NULL,
		0);

	if (report->analysis_time > 0)
	{
		format_time_strings(
			report->analysis_time,
			analysis_at,
			sizeof(analysis_at),
			NULL,
			0,
			NULL,
			0);
	}
	else
	{
		snprintf(analysis_at, sizeof(analysis_at), "%s", generated_at);
	}

	fputs("{\n\"schema\":\"", file);
	fputs(REPORT_SCHEMA_VERSION, file);
	fputs("\",\n\"tool\":{\"name\":\"PE CodeCave\",\"component\":\"structured-report\","
		"\"language\":\"C\",\"score_model\":\"cave+anomaly+section-v1\"},\n", file);
	fputs("\"generated_at\":\"", file);
	fputs(generated_at, file);
	fputs("\",\n\"analysis_time\":", file);
	fprintf(
		file,
		"%lld,\n\"analysis_time_iso\":\"%s\",\n",
		(long long)report->analysis_time,
		analysis_at);

	fputs("\"target\":{\"path\":", file);
	write_json_escaped(file, report->target_file, MAX_PATH);
	fprintf(file, ",\"file_size\":%u,\"pe_image_base\":%llu,", report->pe_info.file_size, (unsigned long long)report->pe_info.image_base);
	fprintf(file, "\"entry_point\":%u,\"entry_point_hex\":\"0x%08X\"},\n", report->pe_info.entry_point, report->pe_info.entry_point);

	fprintf(
		file,
		"\"summary\":{\"risk_score\":%d,\"risk_grade\":\"%s\",\"cave_count\":%u,"
		"\"high_risk_cave_count\":%u,\"anomaly_count\":%u,\"section_count\":%u,"
		"\"executable_section_count\":%u,\"rwx_section_count\":%u,"
		"\"overall_entropy\":%.6f,\"total_cave_bytes\":%u},\n",
		stats->risk_score,
		stats->risk_grade,
		stats->cave_count,
		stats->high_risk_caves,
		stats->anomaly_count,
		section_count,
		stats->executable_sections,
		stats->rwx_sections,
		report->pe_info.overall_entropy,
		stats->total_cave_bytes);

	fprintf(
		file,
		"\"score_breakdown\":{\"cave_component\":%.4f,\"anomaly_component\":%.4f,"
		"\"section_component\":%.4f,\"high_risk_threshold\":%.2f,"
		"\"max_suspicion\":%.6f,\"average_suspicion\":%.6f},\n",
		stats->cave_component,
		stats->anomaly_component,
		stats->section_component,
		REPORT_HIGH_RISK_THRESHOLD,
		stats->max_suspicion,
		stats->average_suspicion);

	fprintf(
		file,
		"\"cave_types\":{\"zero_fill\":%u,\"pattern_fill\":%u,\"section_gap\":%u,\"overlay\":%u},\n",
		stats->zero_fill_caves,
		stats->pattern_fill_caves,
		stats->gap_caves,
		stats->overlay_caves);

	fprintf(
		file,
		"\"anomaly_severity\":{\"low\":%u,\"medium\":%u,\"high\":%u,\"critical\":%u},\n",
		stats->severity_counts[ANOMALY_SEVERITY_LOW],
		stats->severity_counts[ANOMALY_SEVERITY_MEDIUM],
		stats->severity_counts[ANOMALY_SEVERITY_HIGH],
		stats->severity_counts[ANOMALY_SEVERITY_CRITICAL]);

	write_json_sections(file, report);
	fputs(",\n", file);
	write_json_caves(file, report, stats);
	fputs(",\n", file);
	write_json_anomalies(file, report, stats);
	fputs(",\n", file);
	write_json_recommendations(file, report, stats);
	fputs(",\n\"notes\":[\"Static heuristics are triage signals, not a malware verdict.\","
		"\"Review findings in context before remediation.\"]\n}\n", file);
}

analysis_result_t generate_html_report(const analysis_report_t* report, const config_t* config)
{
	char output_path[MAX_PATH];
	report_stats_t stats;
	FILE* file;
	analysis_result_t result;

	if (!report || !config)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	result = build_report_path(
		report,
		config,
		"html",
		output_path,
		sizeof(output_path),
		NULL,
		0);
	if (result != RESULT_SUCCESS)
	{
		return result;
	}

	collect_report_stats(report, &stats);
	file = fopen(output_path, "wb");
	if (!file)
	{
		return RESULT_ERROR_ANALYSIS_FAILED;
	}

	write_html_report(file, report, &stats);
	if (ferror(file))
	{
		fclose(file);
		return RESULT_ERROR_ANALYSIS_FAILED;
	}
	if (fclose(file) != 0)
	{
		return RESULT_ERROR_ANALYSIS_FAILED;
	}

	log_message(LOG_LEVEL_INFO, "HTML report: %s", output_path);
	return RESULT_SUCCESS;
}

analysis_result_t generate_json_report(const analysis_report_t* report, const config_t* config)
{
	char output_path[MAX_PATH];
	report_stats_t stats;
	FILE* file;
	analysis_result_t result;

	if (!report || !config)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	result = build_report_path(
		report,
		config,
		"json",
		output_path,
		sizeof(output_path),
		NULL,
		0);
	if (result != RESULT_SUCCESS)
	{
		return result;
	}

	collect_report_stats(report, &stats);
	file = fopen(output_path, "wb");
	if (!file)
	{
		return RESULT_ERROR_ANALYSIS_FAILED;
	}

	write_json_report(file, report, &stats);
	if (ferror(file))
	{
		fclose(file);
		return RESULT_ERROR_ANALYSIS_FAILED;
	}
	if (fclose(file) != 0)
	{
		return RESULT_ERROR_ANALYSIS_FAILED;
	}

	log_message(LOG_LEVEL_INFO, "JSON report: %s", output_path);
	return RESULT_SUCCESS;
}

static analysis_result_t open_report_with_system(const char* report_path)
{
	HINSTANCE shell_result;

	if (!report_path || report_path[0] == '\0')
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	shell_result = ShellExecuteA(
		NULL,
		"open",
		report_path,
		NULL,
		NULL,
		SW_SHOWNORMAL);

	if ((INT_PTR)shell_result <= 32)
	{
		log_message(LOG_LEVEL_ERROR, "Unable to open report: %s", report_path);
		return RESULT_ERROR_ANALYSIS_FAILED;
	}

	return RESULT_SUCCESS;
}

analysis_result_t generate_and_open_html_report(const analysis_report_t* report, const config_t* config)
{
	char output_path[MAX_PATH];
	analysis_result_t result;

	if (!report || !config)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	result = generate_html_report(report, config);
	if (result != RESULT_SUCCESS)
	{
		return result;
	}

	result = build_report_path(
		report,
		config,
		"html",
		output_path,
		sizeof(output_path),
		NULL,
		0);
	if (result != RESULT_SUCCESS)
	{
		return result;
	}

	result = open_report_with_system(output_path);
	if (result == RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_INFO, "HTML report opened: %s", output_path);
	}
	return result;
}

analysis_result_t generate_and_open_json_report(const analysis_report_t* report, const config_t* config)
{
	char output_path[MAX_PATH];
	analysis_result_t result;

	if (!report || !config)
	{
		return RESULT_ERROR_INVALID_PARAMETER;
	}

	result = generate_json_report(report, config);
	if (result != RESULT_SUCCESS)
	{
		return result;
	}

	result = build_report_path(
		report,
		config,
		"json",
		output_path,
		sizeof(output_path),
		NULL,
		0);
	if (result != RESULT_SUCCESS)
	{
		return result;
	}

	result = open_report_with_system(output_path);
	if (result == RESULT_SUCCESS)
	{
		log_message(LOG_LEVEL_INFO, "JSON report opened: %s", output_path);
	}
	return result;
}
