#define LOKI_MODULE
#include "loki_services.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <time.h>
#else
#include <sys/time.h>
#endif

#ifndef LK_DEFAULT_LOGPATH
# define LK_DEFAULT_LOGPATH "logs/%S_%Y%M%D.%I.log"
#endif
#define LK_MAX_CONFIGNAME  64
#define LK_MAX_CONFIGPATH  256

typedef struct lk_LogHeader {
    const char *level;
    const char *service;
    const char *tag;
    const char *key;
    const char *msg;
    size_t      msglen;
    lk_Buffer   buff;
} lk_LogHeader;

typedef enum lk_ConfigMaskFlag {
    lk_Mreload   = 1 << 0,
    lk_Mcolor    = 1 << 1,
    lk_Mscreen   = 1 << 2,
    lk_Mtimeshow = 1 << 3,
    lk_Mlineshow = 1 << 4,
    lk_Minterval = 1 << 5,
    lk_Mfilepath = 1 << 6
} lk_ConfigMaskFlag;

typedef struct lk_Dumper {
    char   name[LK_MAX_CONFIGPATH];
    int    index;
    int    interval;
    time_t next_update;
    FILE  *fp;
} lk_Dumper;

typedef struct lk_LogConfig {
    char name[LK_MAX_CONFIGNAME];
    char filepath[LK_MAX_CONFIGPATH];
    unsigned mask;
    int color; /* 1248:RGBI, low 4bit: fg, high 4bit: bg */
    int screen;
    int timeshow;
    int lineshow;
    int interval;
    lk_Dumper *dumper;
} lk_LogConfig;

typedef struct lk_LogState {
    lk_State *S;
    lk_Table  config;
    lk_Table  dump;
} lk_LogState;

#define lkL_readinteger(ls, buff, config, key)    do { \
    char *s;                                           \
    lk_resetbuffer(buff);                              \
    lk_addfstring(buff, "log.%s." #key, config->name); \
    if ((s = lk_getconfig(ls->S, lk_buffer(buff)))) {  \
        config->key = atoi(s);                         \
        config->mask |= lk_M##key;                     \
        lk_free(ls->S, s); }                         } while(0)

#define lkL_readstring(ls, buff, config, key)     do { \
    char *s;                                           \
    lk_resetbuffer(buff);                              \
    lk_addfstring(buff, "log.%s." #key, config->name); \
    if ((s = lk_getconfig(ls->S, lk_buffer(buff)))) {  \
        lk_strcpy(config->key, lk_buffer(buff),        \
                LK_MAX_CONFIGPATH);                    \
        config->mask |= lk_M##key;                     \
        lk_free(ls->S, s); }                         } while(0)


/* config dumper */

static void lkL_localtime(time_t t, struct tm *tm)
#ifdef _MSC_VER
{ localtime_s(tm, &t); }
#elif _POSIX_SOURCE
{ localtime_r(&t, tm); }
#else
{ *tm = *localtime(&t); }
#endif 

static void lkL_settime(lk_Dumper* dumper, int interval) {
    struct tm tm;
    time_t now = time(NULL), daytm;
    lkL_localtime(now, &tm);
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    daytm = mktime(&tm);
    dumper->interval = interval;
    dumper->index = (int)((now - daytm) / interval);
    dumper->next_update = daytm + (dumper->index + 1) * interval;
}

static void lkL_openfile(lk_LogState *ls, lk_Dumper* dumper) {
    lk_Buffer buff;
    struct tm tm;
    const char *s;
    lkL_localtime(time(NULL), &tm);
    lk_initbuffer(ls->S, &buff);
    for (s = dumper->name; *s != '\0'; ++s) {
        if (*s != '%') {
            lk_addchar(&buff, *s);
            continue;
        }
        switch (*++s) {
        case 'Y': lk_addfstring(&buff, "%04d", tm.tm_year + 1900); break;
        case 'M': lk_addfstring(&buff, "%02d", tm.tm_mon + 1); break;
        case 'D': lk_addfstring(&buff, "%02d", tm.tm_mday); break;
        case 'I': lk_addfstring(&buff, "%d", dumper->index + 1); break;
        default:  lk_addchar(&buff, '%'); /* FALLTHROUGH */
        case '%': lk_addchar(&buff, *s); break;
        }
    }
    lk_addchar(&buff, '\0');
#ifdef _MSC_VER
    fopen_s(&dumper->fp, lk_buffer(&buff), "a");
#else
    dumper->fp = fopen(lk_buffer(&buff), "a");
#endif
    lk_freebuffer(&buff);
}

static lk_Dumper *lkL_newdumper(lk_LogState *ls, lk_LogConfig *config, lk_LogHeader *hs) {
    const char *s;
    lk_Buffer buff;
    lk_Dumper *dumper;
    lk_Entry *e;
    if (!(config->mask & lk_Mfilepath))
        return NULL;
    lk_initbuffer(ls->S, &buff);
    for (s = config->filepath; *s != '\0'; ++s) {
        if (*s != '%') {
            lk_addchar(&buff, *s);
            continue;
        }
        switch (*++s) {
        case 'L': lk_addstring(&buff, hs->level); break;
        case 'S': lk_addstring(&buff, hs->service); break;
        case 'T': lk_addstring(&buff, hs->tag); break;
        default:  lk_addchar(&buff, '%');
                  lk_addchar(&buff, *s); break;
        }
    }
    lk_addchar(&buff, '\0');
    e = lk_setentry(&ls->dump, lk_buffer(&buff));
    if (e->value != NULL) return (lk_Dumper*)e->value;
    dumper = (lk_Dumper*)lk_malloc(ls->S, sizeof(lk_Dumper));
    memset(dumper, 0, sizeof(*dumper));
    e->value = dumper;
    lk_strcpy(dumper->name, lk_buffer(&buff), LK_MAX_CONFIGPATH);
    lk_freebuffer(&buff);
    if (config->interval > 0)
        lkL_settime(dumper, config->interval);
    lkL_openfile(ls, dumper);
    return dumper;
}

static int lkL_wheelfile(lk_LogState* ls, lk_Dumper* dumper) {
    if (time(NULL) > dumper->next_update) {
        if (dumper->fp) fclose(dumper->fp);
        lkL_settime(dumper, dumper->interval);
        lkL_openfile(ls, dumper);
    }
    return 0;
}


/* config reader */

static lk_LogConfig *lkL_newconfig(lk_LogState *ls, const char *name) {
    lk_Entry *e = lk_setentry(&ls->config, name);
    lk_LogConfig *config = (lk_LogConfig*)e->value;
    if (config) return config;
    config = (lk_LogConfig*)lk_malloc(ls->S, sizeof(lk_LogConfig));
    memset(config, 0, sizeof(*config));
    lk_strcpy(config->name, name, LK_MAX_CONFIGNAME);
    config->mask |= lk_Mreload;
    config->timeshow = 1;
    config->lineshow = 1;
    config->color = 0x77;
    e->key   = config->name;
    e->value = config;
    return config;
}

static lk_LogConfig* lkL_getconfig(lk_LogState *ls, const char *name) {
    lk_LogConfig *config = lkL_newconfig(ls, name);
    if (config->mask & lk_Mreload) {
        lk_Buffer buff;
        lk_initbuffer(ls->S, &buff);
        lkL_readinteger(ls, &buff, config, color);
        lkL_readinteger(ls, &buff, config, screen);
        lkL_readinteger(ls, &buff, config, timeshow);
        lkL_readinteger(ls, &buff, config, lineshow);
        lkL_readinteger(ls, &buff, config, interval);
        lkL_readstring(ls,  &buff, config, filepath);
        lk_freebuffer(&buff);
    }
    return config;
}

static int lkL_mergeconfig(lk_LogConfig *c1, lk_LogConfig *c2) {
    if (c1 == NULL || c2 == NULL) return -1;
    if (c2->mask & lk_Mcolor)    c1->color = c2->color;
    if (c2->mask & lk_Mscreen)   c1->screen = c2->screen;
    if (c2->mask & lk_Mtimeshow) c1->timeshow = c2->timeshow;
    if (c2->mask & lk_Mlineshow) c1->lineshow = c2->lineshow;
    if (c2->mask & lk_Minterval) c1->interval = c2->interval;
    if (c2->mask & lk_Mfilepath) lk_strcpy(c1->filepath, c2->filepath, LK_MAX_CONFIGPATH);
    c1->mask |= c2->mask;
    return 0;
}

static lk_LogConfig* lkL_setconfig(lk_LogState *ls, lk_LogHeader *hs) {
    lk_LogConfig *config = lkL_getconfig(ls, hs->key);
    if (config->mask & lk_Mreload) {
        lk_LogConfig *other = lkL_getconfig(ls, hs->level);
        config->screen = 1;
        if (other->mask != lk_Mreload)
            lkL_mergeconfig(config, other);
        other = lkL_getconfig(ls, hs->service);
        if (other->mask == lk_Mreload)
            other = lkL_getconfig(ls, "default_service");
        if (other->mask != lk_Mreload)
            lkL_mergeconfig(config, other);
        if (hs->tag) {
            other = lkL_getconfig(ls, hs->tag);
            if (other->mask != lk_Mreload)
                lkL_mergeconfig(config, other);
        }
        if ((config->mask & lk_Mfilepath) && config->dumper == NULL)
            config->dumper = lkL_newdumper(ls, config, hs);
        config->mask &= ~lk_Mreload;
    }
    return config;
}


/* config parser */

static void lkL_parseheader(lk_LogHeader *hs, const char* service, const char* s, size_t len) {
    const char *end = s + len;
    size_t offset_key = 0; /* key struct: [level][service][tag] */
    hs->level   = "info";
    hs->service = service;
    hs->tag     = NULL;
    hs->msg = s;
    if (len >= 3 && s[1] == '[') {
        const char *start = s + 2;
        switch (*s) {
        default: goto no_tag;
        case 'I': break;
        case 'T': hs->level = "trace"; break;
        case 'V': hs->level = "verbose"; break;
        case 'W': hs->level = "warning"; break;
        case 'E': hs->level = "error"; break;
        }
        for (s = start; s < end && *s != ']'; ++s)
            ;
        if (s == end) goto no_tag;
        if (s - start != 0) {
            lk_addlstring(&hs->buff, start, s - start);
            lk_addchar(&hs->buff, '\0');
            offset_key = lk_buffsize(&hs->buff);
        }
        hs->msg = *++s == ' ' ? s + 1 : s;
    }
no_tag:
    hs->msglen = end - hs->msg;
    lk_addfstring(&hs->buff, "[%s][%s][", hs->level, service);
    if (offset_key != 0) {
        lk_prepbuffsize(&hs->buff, offset_key-1);
        lk_addlstring(&hs->buff, lk_buffer(&hs->buff), offset_key-1);
        hs->tag = lk_buffer(&hs->buff);
    }
    lk_addlstring(&hs->buff, "]\0", 2);
    hs->key = lk_buffer(&hs->buff) + offset_key;
}

static void lkL_screendump(lk_LogState *ls, const char *s, size_t len, int color)  {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD attr = 0, reset = FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE;
    DWORD written;
    LPWSTR buff = NULL;
    int bytes, cp = CP_UTF8;
    if (color & 0x01) attr |= FOREGROUND_RED;
    if (color & 0x02) attr |= FOREGROUND_GREEN;
    if (color & 0x04) attr |= FOREGROUND_BLUE;
    if (color & 0x08) attr |= FOREGROUND_INTENSITY;
    if (color & 0x10) attr |= BACKGROUND_RED;
    if (color & 0x20) attr |= BACKGROUND_GREEN;
    if (color & 0x40) attr |= BACKGROUND_BLUE;
    if (color & 0x80) attr |= BACKGROUND_INTENSITY;
    bytes = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, len, NULL, 0);
    if (bytes != 0) {
        buff = (LPWSTR)lk_malloc(ls->S, bytes * sizeof(WCHAR));
        bytes = MultiByteToWideChar(cp, 0, s, len, buff, bytes);
    }
    SetConsoleTextAttribute(h, attr);
    if (buff) WriteConsoleW(h, buff, bytes, &written, NULL);
    else      WriteConsoleA(h, s, len, &written, NULL);
    SetConsoleTextAttribute(h, reset);
    fputc('\n', stdout);
    lk_free(ls->S, buff);
#else
    int fg = 30 + (color & 0x7), bg = 40 + ((color & 0x70)>>4);
    if (color & 0x08) fg += 60;
    if (color & 0x80) bg += 60;
    fprintf(stdout, "\e[%d;%dm%.*s\e[0m", fg, bg, len, s);
#endif
}

static void lkL_filedump(lk_LogState *ls, const char *s, size_t len, lk_Dumper *dumper) {
    if (dumper->interval > 0 || !dumper->fp)
        lkL_wheelfile(ls, dumper);
    if (dumper->fp) {
        fwrite(s, 1, len, dumper->fp);
        fputc('\n', dumper->fp);
        fflush(dumper->fp);
    }
}

static int lkL_writelog(lk_LogState *ls, const char* service_name, char* s, size_t len) {
    lk_LogConfig *config;
    lk_LogHeader hs;
    struct tm tm;

    lk_initbuffer(ls->S, &hs.buff);
    lkL_parseheader(&hs, service_name, s, len);
    lkL_localtime(time(NULL), &tm);
    if (hs.tag) fprintf(stdout, "[%c][%s][%02d:%02d:%02d][%s]: ", 
            toupper(hs.level[0]), service_name,
            tm.tm_hour, tm.tm_min, tm.tm_sec, hs.tag);
    else fprintf(stdout, "[%c][%s][%02d:%02d:%02d]: ", 
            toupper(hs.level[0]), service_name,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    config = lkL_setconfig(ls, &hs);
    if (config->screen)
        lkL_screendump(ls, hs.msg, hs.msglen, config->color);
    if (config->dumper)
        lkL_filedump(ls, hs.msg, hs.msglen, config->dumper);
    lk_freebuffer(&hs.buff);
    return 0;
}


/* config initialize */

static void lkL_initlog(lk_LogState *ls) {
    lk_LogConfig *config;
    lk_inittable(ls->S, &ls->config);
    lk_inittable(ls->S, &ls->dump);

    /* initialize config */
    config = lkL_newconfig(ls, "info");
    config->screen = 1;
    config->color = 0x07;
    config->mask = lk_Mscreen|lk_Mcolor;
    config = lkL_newconfig(ls, "trace");
    config->screen = 1;
    config->color = 0x0F;
    config->mask = lk_Mscreen|lk_Mcolor;
    config = lkL_newconfig(ls, "verbose");
    config->screen = 1;
    config->color = 0x70;
    config->mask = lk_Mscreen|lk_Mcolor;
    config = lkL_newconfig(ls, "warning");
    config->screen = 1;
    config->color = 0x0B;
    config->mask = lk_Mscreen|lk_Mcolor;
    config = lkL_newconfig(ls, "error");
    config->screen = 1;
    config->color = 0x9F;
    config->mask = lk_Mscreen|lk_Mcolor;
    config = lkL_newconfig(ls, "default_service");
    lk_strcpy(config->filepath, LK_DEFAULT_LOGPATH, LK_MAX_CONFIGPATH);
    config->interval = 3600;
    config->mask = lk_Mfilepath|lk_Minterval;
}

static void lkL_freelog(lk_LogState* ls) {
    lk_Entry *e = NULL;
    while (lk_nextentry(&ls->config, &e)) {
        lk_LogConfig *config = (lk_LogConfig*)e->value;
        lk_free(ls->S, config);
    }
    while (lk_nextentry(&ls->dump, &e)) {
        lk_Dumper *dumper = (lk_Dumper*)e->value;
        if (dumper->fp) fclose(dumper->fp);
        lk_free(ls->S, dumper);
    }
    lk_freetable(&ls->config, 0);
    lk_freetable(&ls->dump, 0);
    lk_free(ls->S, ls);
}

static int lkL_write(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)ud;
    if (!sig) lkL_freelog(ls);
    else if (sig->data)
        lkL_writelog(ls, lk_name((lk_Slot*)sig->src), (char*)sig->data, sig->size);
    return LK_OK;
}

static int lkL_update(lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)ud;
    lk_Entry *e = NULL;
    while (lk_nextentry(&ls->config, &e)) {
        lk_LogConfig *config = (lk_LogConfig*)e->value;
        config->mask |= lk_Mreload;
        config->dumper = NULL;
    }
    while (lk_nextentry(&ls->dump, &e)) {
        lk_Dumper *dumper = (lk_Dumper*)e->value;
        if (dumper->fp) fclose(dumper->fp);
        lk_free(ls->S, dumper);
    }
    lk_freetable(&ls->dump, 0);
    return LK_OK;
}

LKMOD_API int loki_service_log(lk_State *S) {
    lk_Service *svr = lk_self(S);
    lk_LogState *ls = (lk_LogState*)lk_malloc(S, sizeof(lk_LogState));
    ls->S = S;
    lk_setdata(S, ls);
    lk_setslothandler((lk_Slot*)svr, lkL_write, ls);
    lkL_initlog(ls);
    lk_newslot(S, "update", lkL_update, ls);
    return LK_WEAK;
}

