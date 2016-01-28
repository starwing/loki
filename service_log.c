#define LOKI_MODULE
#include "loki_services.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LK_DEFAULT_LEN  64
#define LK_KEY_LEN		64
#define LK_FPATH_LEN	64

#define lkL_readconfig_int(name, config, key) \
    do { \
        char name##_key[LK_KEY_LEN]; \
        sprintf(name##_key, "%s."#name, key); \
        char *name##_str = lk_getconfig(ls->S, name##_key); \
        if (name##_str) { \
            config->name = atoi(name##_str); \
            config->maskflag |= lk_em_##name; \
        } \
    } while(0)

#define lkL_readconfig_str(name, config, key) \
    do { \
        char name##_key[LK_KEY_LEN]; \
        sprintf(name##_key, "%s."#name, key); \
        char *name##_str = lk_getconfig(ls->S, name##_key); \
        if (name##_str) { \
            strcpy(config->name, name##_str); \
            config->maskflag |= lk_em_##name; \
        } \
    } while(0)

#ifndef _WIN32
static const char* log_color[] = {
    "\e[1m\e[31m", /* error */
    "\e[1m\e[32m", /* warning */
    "\e[1m\e[37m", /* debug */
    "\e[1m\e[37m", /* trace */
};
static const char* color_end = "\e[m";
#endif

typedef enum lk_LogLevel {
    log_lvl_error = 0,
    log_lvl_warning,
    log_lvl_debug,
    log_lvl_trace,
    log_lvl_max
} lk_LogLevel;

typedef enum lk_ConfigMaskFlag {
    lk_em_loglv     = 1,
    lk_em_screen    = 1 << 1,
    lk_em_timeshow  = 1 << 2,
    lk_em_lineshow  = 1 << 3,
    lk_em_interval  = 1 << 4,
    lk_em_filepath  = 1 << 5
} lk_ConfigMaskFlag;

typedef struct lk_LogDump {
	int wheel_index;
	int wheel_interval;
	time_t next_wheeltm;
	time_t next_daytm;
	char file_path[LK_FPATH_LEN];
	FILE *fp;
} lk_LogDump;

typedef struct lk_LogConfig {
    int maskflag;
	int loglv;
	int screen;
	int timeshow;
	int lineshow;
	int interval;
	char filepath[LK_FPATH_LEN];
    lk_LogDump *logdump;
} lk_LogConfig;

typedef struct lk_LogState {
	lk_State *S;
	lk_Table config;
	lk_Table dump;
} lk_LogState;

LK_API int lk_logemit(lk_Service* svr, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);

    lk_LogState *ls = (lk_LogState *)lk_data(svr);
    lk_Buffer log_buff;
    lk_initbuffer(ls->S, &log_buff);
    lk_addvfstring(&log_buff, fmt, ap);

    lk_Signal log_sig = {NULL};
    log_sig.copy = 1;
    log_sig.size = lk_buffsize(&log_buff);
    log_sig.data = lk_buffer(&log_buff);
    lk_emit((lk_Slot*)svr, &log_sig);
    lk_freebuffer(&log_buff);

    va_end(ap);
    return 0;
}

static int lkL_openfile(lk_LogState *ls, lk_LogDump* dump, const char* name) {
    struct tm tm;
    time_t now = time(0);
    tm = *localtime(&now);

    lk_Buffer filename;
    lk_initbuffer(ls->S, &filename);
    lk_addfstring(&filename, "%s%s_%4d%02d%02d%05d.log",
        dump->file_path, name, tm.tm_year+1900, 
        tm.tm_mon+1, tm.tm_mday, dump->wheel_index);

    FILE *fp = fopen(lk_buffer(&filename),"ab+");
    if (fp != NULL) {
        fseek(fp,0,0);
    }
    dump->fp = fp;
    return 0;
}

static void lkL_initconfig(lk_LogConfig* config) {
    config->maskflag = 0;
    config->screen = -1;
    config->timeshow = 1;
    config->lineshow = 1;
    config->interval = 0;
    config->loglv = log_lvl_debug;
    memset(config->filepath, 0, sizeof(config->filepath));
    config->logdump = NULL;
}

static int lkL_mergeconfig(lk_LogConfig *c1, lk_LogConfig *c2) {
    if (c1 == NULL || c2 == NULL) return -1;
    if (c2->maskflag & lk_em_screen) c1->screen = c2->screen;
    if (c2->maskflag & lk_em_timeshow) c1->timeshow = c2->timeshow;
    if (c2->maskflag & lk_em_lineshow) c1->lineshow = c2->lineshow;
    if (c2->maskflag & lk_em_interval) c1->interval = c2->interval;
    if (c2->maskflag & lk_em_filepath) strcpy(c1->filepath, c2->filepath);
    if (c2->logdump) c1->logdump = c2->logdump;
    return 0;
}

static lk_LogConfig* lkL_readconfig(lk_LogState *ls, const char *key) {
    lk_LogConfig *config = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
    lkL_initconfig(config);

    lkL_readconfig_int(loglv, config, key);
    lkL_readconfig_int(screen, config, key);
    lkL_readconfig_int(timeshow, config, key);
    lkL_readconfig_int(lineshow, config, key);
    lkL_readconfig_int(interval, config, key);
    lkL_readconfig_str(filepath, config, key);

    return config;
}

static lk_LogConfig* lkL_getconfig(lk_LogState* ls, const char *key) {
    lk_Entry *e = lk_getentry(&ls->config, key);
    if (e == NULL) {
        e = lk_setentry(&ls->config, key);
        e->value = lkL_readconfig(ls, key);
    } 
    return (lk_LogConfig*)e->value;
}

static int lkL_wheelindex(lk_LogDump* dump) {
    if (dump->wheel_interval == 0) return 0;

	struct tm tm;
	time_t now = time(0);
	tm = *localtime(&now);
	tm.tm_hour = 0;
	tm.tm_min = 0;
	tm.tm_sec = 0;
	time_t daytm = mktime(&tm);

    int index = (now - daytm) / dump->wheel_interval;
    dump->wheel_index = index;
    dump->next_wheeltm = daytm + (index + 1) * dump->wheel_interval;
    dump->next_daytm = daytm + 3600 * 24;
    return 0;
}

static int lkL_wheelfile(lk_LogState* ls, lk_LogDump* dump, const char* key) {
    time_t now = time(0);
    if ( now > dump->next_daytm || now > dump->next_wheeltm) {
        char loglv[4];
        char svrname[LK_DEFAULT_LEN];
        sscanf(key, "%c,%s", loglv, svrname);
    
        if (dump->fp) fclose(dump->fp);
        lkL_wheelindex(dump);
        lkL_openfile(ls, dump, key);
    }
    return 0;
}

static int lkL_setdump(lk_LogState *ls, const char* key, lk_LogConfig* c) {
    lk_Entry *e = lk_setentry(&ls->dump, key);
    if (e->value == NULL) {
        lk_LogDump *d = (lk_LogDump*)lk_malloc(ls->S, sizeof(lk_LogDump));
        d->wheel_interval = c->interval;
        strcpy(d->file_path, c->filepath);
        lkL_wheelindex(d);
        lkL_openfile(ls, d, key);
        e->value = d;
    }
    c->logdump = (lk_LogDump*)e->value;
    return 0;
}

static lk_LogConfig* lkL_setconfig(lk_LogState *ls, const char* key) {
    lk_Entry *e = lk_setentry(&ls->config, key);
    if (e->value == NULL) {
        lk_LogConfig *config = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
        lkL_initconfig(config);

        char loglv[4];
        char svrname[LK_DEFAULT_LEN];
        sscanf(key, "%c,%s", loglv, svrname);
        lk_LogConfig* lvc = lkL_getconfig(ls, loglv);
        if (lvc) {
            lkL_mergeconfig(config, lvc);
        } else {
            lk_LogConfig* defc = lkL_getconfig(ls, "defalut");
            lkL_mergeconfig(config, defc);
        }
        lk_LogConfig* svrc = lkL_getconfig(ls, svrname);
        if (svrc) lkL_mergeconfig(config, svrc);

        if (!config->logdump) {
            lkL_setdump(ls, svrname, config);
            if (svrc) svrc->logdump = config->logdump;
        }
        e->value = config;
    } else {
        lk_LogConfig* config = (lk_LogConfig*)e->value;
        if (config->interval > 0) {
        lkL_wheelfile(ls, config->logdump, key);
        }
    }

    return (lk_LogConfig*)e->value;
}

static int lkL_logdump(lk_LogDump *dump, char* buff, int size) {
    if (dump && dump->fp) {
        fwrite(buff, size, 1, dump->fp);
        fflush(dump->fp);
    }
    return 0;
}

static int lkL_writelog(lk_LogState *ls, const char* service_name, char* log_msg) {
    struct tm tm;
    time_t now = time(0);
    tm = *localtime(&now);

    char lv_char = log_msg[0];
    char key[LK_KEY_LEN];
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

    lk_LogConfig* config = lkL_setconfig(ls, key);
    if (config && config->screen == 1) {
#ifdef _WIN32
        fprintf(stdout, "%s", lk_buffer(&log_buff));
#else
        fprintf(stdout, "%s%s%s", log_color[loglv], 
            lk_buffer(&log_buff), color_end);
#endif
    }

    if (config && config->logdump) {
        lkL_logdump(config->logdump, lk_buffer(&log_buff), lk_buffsize(&log_buff));
    }
    lk_freebuffer(&log_buff);
    return 0;
}

static int lkL_initlog(lk_LogState *ls) {
    lk_inittable(ls->S, &ls->config);
    lk_inittable(ls->S, &ls->dump);

    /* test */	
    lk_LogConfig *config = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
    lkL_initconfig(config);
    config->screen = 1;
    config->maskflag |= lk_em_screen;
    config->loglv = log_lvl_debug;
    config->maskflag |= lk_em_loglv;
    lk_Entry *e = lk_setentry(&ls->config, "default");
    e->value = config;

    lk_LogConfig *c = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
    lkL_initconfig(c);
    config->interval = 300;
    config->maskflag |= lk_em_interval;
    strcpy(config->filepath, "./logfile/");
    config->maskflag |= lk_em_filepath;
    lk_Entry *e1 = lk_setentry(&ls->config, "echo");
    e1->value = config;

    return 0;
}

static int lkL_freelog(lk_LogState* ls) {
    size_t i = 0;
    for (i = 0; i < ls->config.size; ++i) {
        void *value = ls->config.hash[i].value;
        if (value != NULL) lk_free(ls->S, value);
    }
    for (i = 0; i < ls->dump.size; ++i) {
        void *value = ls->dump.hash[i].value;
        if (value != NULL) lk_free(ls->S, value);
    }
    lk_freetable(&ls->config);
    lk_freetable(&ls->dump);
    return 0;
}

static int lkL_write(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)ud;
    lkL_writelog(ls, lk_name((lk_Slot*)sig->src), (char*)sig->data);
    return 0;
}

static lk_LogState* lkL_newstate(lk_State *S) {
    lk_LogState *ls = (lk_LogState*)lk_malloc(S, sizeof(lk_LogState));
    ls->S = S;
    return ls;
}

LKMOD_API int loki_service_log(lk_State *S) {
    lk_LogState *ls = lkL_newstate(S);
    lk_Service *svr = lk_self(S);
    lk_setdata(svr, ls);
    lk_setslothandler((lk_Slot*)svr, lkL_write, ls);
	
    lkL_initlog(ls);
    return LK_WEAK;
}

