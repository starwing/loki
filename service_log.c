#define LOKI_MODULE
#include "loki_services.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <time.h>
#include <windows.h>
#else
#include <sys/time.h>
#endif

#define LK_DEFAULT_LEN    64
#define LK_KEY_LEN        64
#define LK_FPATH_LEN      64

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


#ifdef _WIN32
static const int log_color[] = {
    FOREGROUND_RED,
    FOREGROUND_BLUE,
    FOREGROUND_GREEN,
    FOREGROUND_GREEN,
    FOREGROUND_RED|FOREGROUND_BLUE|FOREGROUND_GREEN,
};
#else
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

typedef struct lkL_HeaderState {
    const char    *key;
    const char    *svrname;
    const char    *msgbody;
    char          level[2];
    int           loglv;
    lk_Buffer     tag;
} lkL_HeaderState;

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

static int lkL_openfile(lk_LogState *ls, lk_LogDump* dump, const char* svrname) {
    struct tm tm;
    time_t now = time(0);
    tm = *localtime(&now);

    lk_Buffer filename;
    lk_initbuffer(ls->S, &filename);
    lk_addfstring(&filename, "%s%s_%4d%02d%02d%05d.log",
        dump->file_path, svrname, tm.tm_year + 1900,
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
    if (e == NULL) e = lk_setentry(&ls->config, key);
	if (e->value == NULL) e->value = lkL_readconfig(ls, key);
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

static int lkL_wheelfile(lk_LogState* ls, lk_LogDump* dump, const char* svrname) {
    time_t now = time(0);
    if ( now > dump->next_daytm || now > dump->next_wheeltm) {
        if (dump->fp) fclose(dump->fp);
        lkL_wheelindex(dump);
        lkL_openfile(ls, dump, svrname);
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

static lk_LogConfig* lkL_setconfig(lk_LogState *ls, lkL_HeaderState *hs) {
    lk_Entry *e = lk_setentry(&ls->config, hs->key);
    if (e->value == NULL) {
        lk_LogConfig *config = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
        lkL_initconfig(config);

        lk_LogConfig* lvc = lkL_getconfig(ls, hs->level);
        if (lvc->maskflag == 0) lvc = lkL_getconfig(ls, "lv_default");
        lkL_mergeconfig(config, lvc);
        lk_LogConfig* svrc = lkL_getconfig(ls, hs->svrname);
        if (svrc->maskflag == 0) svrc = lkL_getconfig(ls, "svr_default");
        lkL_mergeconfig(config, svrc);

        if (!config->logdump) {
            lkL_setdump(ls, hs->svrname, config);
            if (svrc) svrc->logdump = config->logdump;
        }
        e->value = config;
    } else {
        lk_LogConfig* config = (lk_LogConfig*)e->value;
        if (config->interval > 0) {
            lkL_wheelfile(ls, config->logdump, hs->svrname);
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


static int lkL_parseheader(char* msg, lkL_HeaderState *hs, const char* svrname) {
    size_t offset_svr = 0; 
    size_t offset_key = 0;
	
    int ch = *msg;
    hs->loglv = log_lvl_trace;
    if (ch == 'D') hs->loglv = log_lvl_debug;
    else if (ch == 'E') hs->loglv = log_lvl_error;
    else if (ch == 'W') hs->loglv = log_lvl_warning;
    hs->level[0] = ch;
    hs->level[1] = '\0';
	
    hs->msgbody = msg;
    if (*++msg == '[') {
        const char *start = ++msg;
        while (*msg != '\0' && *++msg != ']')
            ;
        if (*msg == ']') {
            lk_addlstring(&hs->tag, start, msg - start);
                lk_addchar(&hs->tag, '\0');
                offset_svr = lk_buffsize(&hs->tag);
                hs->msgbody = msg + 1;
        }
        if (*msg == '\0') hs->msgbody = msg;
    }

    lk_addlstring(&hs->tag, svrname, strlen(svrname));
    lk_addchar(&hs->tag, '\0');
    offset_key = lk_buffsize(&hs->tag);
    lk_addfstring(&hs->tag, "[%c][%s][%s]", ch, svrname, lk_buffer(&hs->tag));

    hs->svrname = lk_buffer(&hs->tag) + offset_svr;
    hs->key = lk_buffer(&hs->tag) + offset_key;

    return 0;
}

static int lkL_writelog(lk_LogState *ls, const char* service_name, char* log_msg) {
    struct tm tm;
    time_t now = time(0);
    tm = *localtime(&now);

    if (strlen(log_msg) < 4) return 0;
    lkL_HeaderState hs;
    lk_initbuffer(ls->S, &hs.tag);
    lkL_parseheader(log_msg, &hs, service_name);

    lk_Buffer log_buff;
    lk_initbuffer(ls->S, &log_buff);
    lk_addfstring(&log_buff, "[%s][%s][%02d:%02d:%02d]%s\n", 
        hs.level, service_name, tm.tm_hour, tm.tm_min, 
        tm.tm_sec, hs.msgbody);

    lk_LogConfig* config = lkL_setconfig(ls, &hs);
    if (config && config->screen == 1) {
#ifdef _WIN32
        HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(handle, log_color[hs.loglv]);
        fwrite(lk_buffer(&log_buff), 1, lk_buffsize(&log_buff), stdout);
        SetConsoleTextAttribute(handle, log_color[log_lvl_max]);
#else
        fprintf(stdout, "%s%s%s", log_color[hs.loglv], 
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
    lk_Entry *e = lk_setentry(&ls->config, "lv_default");
    e->value = config;

    lk_LogConfig *c = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
    lkL_initconfig(c);
    config->interval = 300;
    config->maskflag |= lk_em_interval;
    strcpy(config->filepath, "./logfile/");
    config->maskflag |= lk_em_filepath;
    lk_Entry *e1 = lk_setentry(&ls->config, "svr_default");
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
    lk_freetable(&ls->config, 0);
    lk_freetable(&ls->dump, 0);
    return 0;
}

static int lkL_write(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)ud;
    if (!sig)
        lkL_freelog(ls);
    else if (sig->data)
        lkL_writelog(ls, lk_name((lk_Slot*)sig->src), (char*)sig->data);
    return LK_OK;
}

static lk_LogState* lkL_newstate(lk_State *S) {
    lk_LogState *ls = (lk_LogState*)lk_malloc(S, sizeof(lk_LogState));
    ls->S = S;
    return ls;
}

LKMOD_API int loki_service_log(lk_State *S) {
    lk_LogState *ls = lkL_newstate(S);
    lk_Service *svr = lk_self(S);
    lk_setdata(S, ls);
    lk_setslothandler((lk_Slot*)svr, lkL_write, ls);
    lkL_initlog(ls);
    return LK_WEAK;
}

