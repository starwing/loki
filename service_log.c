#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "loki_services.h"

#define DEFAULT_LEN 64
#define KEY_LEN		64
#define FPATH_LEN	64

static const char* log_name[] = {
	"E", //error
	"W", //warning
	"D", //debug
	"T", //trace 
};

static const char* log_color[] = {
	"\e[1m\e[31m", //error
	"\e[1m\e[32m", //warning
	"\e[1m\e[37m", //debug
	"\e[1m\e[37m", //trace
};
static const char* color_end = "\e[m";

typedef struct lk_LogConfig {
	int screen;
	int time_print;
	int fileline_print;
	int log_lv;
	int wheel_interval;
	char file_path[FPATH_LEN];
	
	int wheel_index;
	time_t next_wheeltm;
	FILE *fp;
} lk_LogConfig;

typedef struct lk_LogState {
	lk_State *S;
	lk_Slot  *write;
	lk_Table table; //global TODO:
} lk_LogState;

LK_API int lk_logemit(lk_Service* svr, lk_LogLevel lv, const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	lk_LogState *ls = (lk_LogState *)lk_data(svr);
	lk_Buffer log_buff;
    lk_initbuffer(ls->S, &log_buff);
    lk_addfstring(&log_buff, "%s", log_name[lv]);
    lk_addvfstring(&log_buff, fmt, ap);

	lk_Signal log_sig = {NULL};
	log_sig.copy = 1;
	log_sig.size = lk_buffsize(&log_buff);
	log_sig.data = lk_buffer(&log_buff);
    lk_emit(ls->write, &log_sig);
	lk_freebuffer(&log_buff);

	va_end(ap);
	return 0;
}

static int lkL_openfile(lk_LogState *ls, lk_LogConfig* config, const char* name)
{
	struct tm tm;
	time_t now = time(0);
	localtime_r(&now, &tm);
	
	lk_Buffer filename;
    lk_initbuffer(ls->S, &filename);
    lk_addfstring(&filename, "%s%s%4d%02d%02d%05d",
		config->file_path, name, 
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday,
		config->wheel_index);
	printf("log open fp=%s\n", config->file_path);
	
	config->fp = fopen(lk_buffer(&filename),"ab+");
	if (config->fp != NULL) {
		fseek(config->fp,0,0);
	}
	
	return 0;
}

static int lkL_wheelindex(lk_LogConfig* config)
{
	if (config->wheel_interval == 0) 
		return 0;

	struct tm tm;
	time_t now = time(0);
	localtime_r(&now, &tm);
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	time_t daytm = mktime(&tm);

	int index = (now - daytm) / config->wheel_interval;
	config->wheel_index = index;
	config->next_wheeltm = daytm + (index + 1) * config->wheel_interval;
	printf("config wheel index=%d\n", config->wheel_index);
	return 0;
}

static int lkL_wheelfile(lk_LogState* ls, lk_LogConfig* config, const char* key)
{
	time_t now = time(0);
	if ( now > config->next_wheeltm) {
		if (config->fp) {
			fclose(config->fp);
		}
		config->wheel_index++;
		config->next_wheeltm += config->wheel_interval;
		char loglv[4];
		char svrname[DEFAULT_LEN];
		sscanf(key, "%c,%s", loglv, svrname);
		lkL_openfile(ls, config, svrname);
	}
	return 0;
}

static void lkL_initConfig(lk_LogConfig* config)
{
	config->screen = -1;
	config->time_print = 1;
	config->fileline_print = 1;
	config->log_lv = log_lvl_debug;
	config->wheel_interval = 0;
	
	config->wheel_index = 0;
	config->next_wheeltm = 0;
	memset(config->file_path, 0, sizeof(config->file_path));
	config->fp = NULL;
}

static int lkL_mergeConfig(lk_LogConfig *c1, lk_LogConfig *c2)
{
	if (c1 == NULL || c2 == NULL) return -1;

	if (c2->screen != -1) c1->screen = c2->screen;
	if (c2->time_print != -1) c1->time_print = c2->time_print;
	if (c2->fileline_print != -1) c1->fileline_print = c2->fileline_print;
	if (c2->wheel_interval != -1) c1->wheel_interval = c2->wheel_interval;
	if (strlen(c2->file_path) > 0) strcpy(c1->file_path, c2->file_path);
	//if (c2->fp && !c1->fp) c1->fp = c2->fp; //TODO:
	return 0;
}

static lk_LogConfig* lkL_getConfig(lk_LogState* ls, const char *key)
{
	lk_Entry *e = lk_getentry(&ls->table, key);
	if (e == NULL)
		return NULL;
	return (lk_LogConfig*)e->value;
}

static lk_LogConfig* lkL_setConfig(lk_LogState *ls, const char* key)
{
	lk_Entry *e = lk_setentry(&ls->table, key);
	if (e->value == NULL) {
		lk_LogConfig *config = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
		lkL_initConfig(config);

		char loglv[4];
		char svrname[DEFAULT_LEN];
		sscanf(key, "%c,%s", loglv, svrname);
		lk_LogConfig* lvC = lkL_getConfig(ls, loglv);
		if (lvC) {
			lkL_mergeConfig(config, lvC);
		} else {
			lk_LogConfig* dfC = lkL_getConfig(ls, "defalut");
			lkL_mergeConfig(config, dfC);
		}
		lk_LogConfig* serC = lkL_getConfig(ls, svrname);
		if (serC) lkL_mergeConfig(config, serC);

		lkL_wheelindex(config);
		lkL_openfile(ls, config, svrname);
		e->value = config;
	} else {
		lk_LogConfig* config = (lk_LogConfig*)e->value;
		if (config->wheel_interval > 0) {
			lkL_wheelfile(ls, config, key);
		}
	}

	return (lk_LogConfig*)e->value;
}

static int lkL_readConfigs(lk_LogState *ls)
{
	//TODO:
	return 0;
}

static int lkL_initlog(lk_LogState *ls)
{
	lk_inittable(ls->S, &ls->table);

	lkL_readConfigs(ls);
	
	//test	
	lk_LogConfig *config = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
	lkL_initConfig(config);
	config->screen = 1;
	config->time_print = 0;
	config->fileline_print = 0;
	config->wheel_interval = 300;
	config->log_lv = log_lvl_debug;
	strcpy(config->file_path, "./logfile/");
	lk_Entry *e = lk_setentry(&ls->table, "defalut");
	e->value = config;

	return 0;
}

static int lkL_writelog(lk_LogState *ls, const char* service_name, char* log_msg)
{
	struct tm tm;
	time_t now = time(0);
	localtime_r(&now, &tm);

	char lv_char = log_msg[0];
	char key[KEY_LEN];
	sprintf(key, "%c,%s", lv_char, service_name);

	int loglv = log_lvl_trace;
	if (lv_char == 'D') loglv = log_lvl_debug;
	else if (lv_char == 'E') loglv = log_lvl_error;
	else if (lv_char == 'W') loglv = log_lvl_warning;

	
	lk_Buffer log_buff;
    lk_initbuffer(ls->S, &log_buff);
    lk_addfstring(&log_buff, "[%c][%s] [%02d:%02d:%02d]\t%s\n", 
			lv_char, service_name, tm.tm_hour, tm.tm_min, 
			tm.tm_sec, log_msg+1);

	lk_LogConfig* config = lkL_setConfig(ls, key);

	if (config->screen == 1) {
		fprintf(stdout, "%s%s%s", log_color[loglv], 
				lk_buffer(&log_buff), color_end);
	}

	if (config && config->fp) {
		fwrite(lk_buffer(&log_buff),lk_buffsize(&log_buff),1,config->fp);
	}

	lk_freebuffer(&log_buff);
	//TODO:
	fflush(config->fp);
	return 0;
}

static int lkL_fini()
{
	/*
	size_t i = 0;
	for (i = 0; i < log_table.size; ++i) {
		const char *key = log_table.hash[i].key;
		if (key != NULL) lk_free(g_state, (void*)key);
	}
	lk_freetable(&log_table);
	*/
	return 0;
}

static int lkL_write(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) 
{
	lk_LogState *ls = (lk_LogState*)ud;
	lkL_writelog(ls, lk_name((lk_Slot*)sig->src), (char*)sig->data);
	return 0;
}

static lk_LogState* lkL_newstate(lk_State *S)
{
	lk_LogState *ls = (lk_LogState*)lk_malloc(S, sizeof(lk_LogState));
	ls->S = S;
	return ls;
}

LKMOD_API int loki_service_log(lk_State *S) 
{
	lk_LogState *ls = lkL_newstate(S);
	lk_Service *svr = lk_self(S);
	lk_setdata(svr, ls);
	
	ls->write = lk_newslot(S, "write", lkL_write, ls);
	
	lkL_initlog(ls);
	return LK_WEAK;
}

