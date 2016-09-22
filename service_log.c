#define LOKI_MODULE
#include "loki_services.h"
#include "lk_buffer.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
# include <time.h>
#else
# include <errno.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/time.h>
#endif

#ifndef LK_DEFAULT_LOGPATH
# define LK_DEFAULT_LOGPATH "logs/%Y-%M/%S_%Y-%M-%D-%I.log"
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
    struct tm   tm;
    lk_Buffer   buff;
} lk_LogHeader;

typedef enum lk_ConfigMaskFlag {
    lk_Mreload   = 1 << 0,
    lk_Mcolor    = 1 << 1,
    lk_Minterval = 1 << 2,
    lk_Mfilepath = 1 << 3
} lk_ConfigMaskFlag;

typedef struct lk_Dumper {
    char     name[LK_MAX_CONFIGPATH];
    unsigned index    : 8;
    unsigned interval : 24;
    time_t   next_update;
    FILE    *fp;
} lk_Dumper;

typedef struct lk_LogConfig {
    char name[LK_MAX_CONFIGNAME];
    char filepath[LK_MAX_CONFIGPATH];
    unsigned mask     : 8;
    unsigned color    : 8; /* 1248:RGBI, low 4bit: fg, high 4bit: bg */
    unsigned interval : 24;
    lk_Dumper *dumper;
} lk_LogConfig;

typedef struct lk_LogState {
    lk_State   *S;
    lk_Table   config;
    lk_Table   dump;
    lk_MemPool configs;
    lk_MemPool dumpers;
} lk_LogState;

#define lkX_readinteger(ls, B, config, key)    do { \
    char *s;                                           \
    lk_resetbuffer(B);                              \
    lk_addfstring(B, "log.%s." #key, config->name); \
    config->mask &= ~lk_M##key;                        \
    if ((s = lk_getconfig(ls->S, lk_buffer(B)))) {  \
        config->key = atoi(s);                         \
        config->mask |= lk_M##key;                     \
        lk_deldata(ls->S, (lk_Data*)s); }          } while(0)

#define lkX_readstring(ls, B, config, key)     do { \
    char *s;                                           \
    lk_resetbuffer(B);                              \
    lk_addfstring(B, "log.%s." #key, config->name); \
    config->mask &= ~lk_M##key;                        \
    if ((s = lk_getconfig(ls->S, lk_buffer(B)))) {  \
        lk_strcpy(config->key, lk_buffer(B),        \
                LK_MAX_CONFIGPATH);                    \
        config->mask |= lk_M##key;                     \
        lk_deldata(ls->S, (lk_Data*)s); }            } while(0)


/* config dumper */

static void lkX_localtime(time_t t, struct tm *tm)
#ifdef _MSC_VER
{ localtime_s(tm, &t); }
#elif _POSIX_SOURCE
{ localtime_r(&t, tm); }
#else
{ *tm = *localtime(&t); }
#endif 

static void lkX_settime(lk_Dumper* dumper, int interval) {
    struct tm tm;
    time_t now = time(NULL), daytm;
    lkX_localtime(now, &tm);
    tm.tm_hour = 0;
    tm.tm_min = 0;
    tm.tm_sec = 0;
    daytm = mktime(&tm);
    dumper->interval = interval;
    dumper->index = (int)((now - daytm) / interval);
    dumper->next_update = daytm + (dumper->index + 1) * interval;
}

static void lkX_createdirs(lk_State *S, const char *path) {
    const char *i, *last;
    lk_Buffer B;
    lk_initbuffer(S, &B);
    for (i = last = path; i != '\0'; last = ++i) {
        while (*i != '\0' && *i != '/' && *i != '\\')
            lk_addchar(&B, *i++);
        if (*i == '\0') break;
        switch (last - i) {
        case 0: continue;
        case 1: if (*last == '.') continue; break;
        case 2: if (last[0] == '.' && last[1] == '.') continue; break;
        }
        lk_addchar(&B, '/');
        *lk_prepbuffsize(&B, 1) = '\0';
#if _WIN32
        if (!CreateDirectoryA(lk_buffer(&B), NULL)
                && GetLastError() != ERROR_ALREADY_EXISTS)
            break;
#else
        if (mkdir(lk_buffer(&B), 0777) < 0 && errno != EEXIST)
            break;
#endif
    }
    lk_freebuffer(&B);
}

static void lkX_escapefn(lk_Buffer *B, const char *s, int idx) {
    struct tm tm;
    lkX_localtime(time(NULL), &tm);
    for (; *s != '\0'; ++s) {
        if (*s != '%') {
            lk_addchar(B, *s);
            continue;
        }
        switch (*++s) {
        case 'Y':  lk_addfstring(B, "%04d", tm.tm_year + 1900); break;
        case 'M':  lk_addfstring(B, "%02d", tm.tm_mon + 1); break;
        case 'D':  lk_addfstring(B, "%02d", tm.tm_mday); break;
        case 'I':  lk_addfstring(B, "%d", idx); break;
        case '\0': lk_addchar(B, '%'); --s; break;
        default:   lk_addchar(B, '%'); /* FALLTHROUGH */
        case '%':  lk_addchar(B, *s); break;
        }
    }
    lk_addchar(B, '\0');
}

static void lkX_openfile(lk_LogState *ls, lk_Dumper* dumper) {
    lk_Buffer B;
    lk_initbuffer(ls->S, &B);
    lkX_escapefn(&B, dumper->name, dumper->index);
    lkX_createdirs(ls->S, lk_buffer(&B));
#ifdef _MSC_VER
    fopen_s(&dumper->fp, lk_buffer(&B), "a");
#else
    dumper->fp = fopen(lk_buffer(&B), "a");
#endif
    lk_freebuffer(&B);
}

static lk_Dumper *lkX_newdumper(lk_LogState *ls, lk_LogConfig *config, lk_LogHeader *hs) {
    const char *s;
    lk_Buffer B;
    lk_Dumper *dumper;
    lk_Entry *e;
    if (!(config->mask & lk_Mfilepath))
        return NULL;
    lk_initbuffer(ls->S, &B);
    for (s = config->filepath; *s != '\0'; ++s) {
        if (*s != '%') {
            lk_addchar(&B, *s);
            continue;
        }
        switch (*++s) {
        case 'L': lk_addstring(&B, hs->level); break;
        case 'S': lk_addstring(&B, hs->service); break;
        case 'T': lk_addstring(&B, hs->tag); break;
        default:  lk_addchar(&B, '%');
                  lk_addchar(&B, *s); break;
        }
    }
    lk_addchar(&B, '\0');
    e = lk_settable(ls->S, &ls->dump, lk_buffer(&B));
    if (e->key != lk_buffer(&B)) return (lk_Dumper*)e->key;
    dumper = (lk_Dumper*)lk_poolalloc(ls->S, &ls->dumpers);
    memset(dumper, 0, sizeof(*dumper));
    lk_strcpy(dumper->name, lk_buffer(&B), LK_MAX_CONFIGPATH);
    lk_freebuffer(&B);
    if (config->interval > 0)
        lkX_settime(dumper, config->interval);
    lkX_openfile(ls, dumper);
    e->key = dumper->name;
    return dumper;
}

static int lkX_wheelfile(lk_LogState* ls, lk_Dumper* dumper) {
    if (time(NULL) > dumper->next_update) {
        if (dumper->fp) fclose(dumper->fp);
        lkX_settime(dumper, dumper->interval);
        lkX_openfile(ls, dumper);
    }
    return 0;
}


/* config reader */

static lk_LogConfig *lkX_newconfig(lk_LogState *ls, const char *name) {
    lk_Entry *e = lk_settable(ls->S, &ls->config, name);
    lk_LogConfig *config = (lk_LogConfig*)e->key;
    if (e->key != name) return config;
    config = (lk_LogConfig*)lk_poolalloc(ls->S, &ls->configs);
    memset(config, 0, sizeof(*config));
    lk_strcpy(config->name, name, LK_MAX_CONFIGNAME);
    config->mask |= lk_Mreload;
    config->color = 0x77;
    e->key = config->name;
    return config;
}

static lk_LogConfig* lkX_getconfig(lk_LogState *ls, const char *name) {
    lk_LogConfig *config = lkX_newconfig(ls, name);
    if (config->mask & lk_Mreload) {
        lk_Buffer B;
        lk_initbuffer(ls->S, &B);
        lkX_readinteger(ls, &B, config, color);
        lkX_readinteger(ls, &B, config, interval);
        lkX_readstring(ls,  &B, config, filepath);
        if (config->interval > 60 * 60 * 24)
            config->interval = 60 * 60 * 24;
        lk_freebuffer(&B);
    }
    return config;
}

static int lkX_mergeconfig(lk_LogConfig *c1, lk_LogConfig *c2) {
    if (c1 == NULL || c2 == NULL) return -1;
    if (c2->mask & lk_Mcolor)    c1->color = c2->color;
    if (c2->mask & lk_Minterval) c1->interval = c2->interval;
    if (c2->mask & lk_Mfilepath) lk_strcpy(c1->filepath, c2->filepath, LK_MAX_CONFIGPATH);
    c1->mask |= c2->mask;
    return 0;
}

static lk_LogConfig* lkX_setconfig(lk_LogState *ls, lk_LogHeader *hs) {
    lk_LogConfig *config = lkX_getconfig(ls, hs->key);
    if (config->mask & lk_Mreload) {
        lk_LogConfig *other = lkX_getconfig(ls, hs->level);
        if (other->mask != lk_Mreload)
            lkX_mergeconfig(config, other);
        other = lkX_getconfig(ls, hs->service);
        if (other->mask == lk_Mreload)
            other = lkX_getconfig(ls, "default_service");
        if (other->mask != lk_Mreload)
            lkX_mergeconfig(config, other);
        if (hs->tag) {
            other = lkX_getconfig(ls, hs->tag);
            if (other->mask != lk_Mreload)
                lkX_mergeconfig(config, other);
        }
        if ((config->mask & lk_Mfilepath) && config->dumper == NULL)
            config->dumper = lkX_newdumper(ls, config, hs);
        config->mask &= ~lk_Mreload;
    }
    return config;
}


/* config parser */

static void lkX_parseheader(lk_LogHeader *hs, const char* service, const char* s, size_t len) {
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

static void lkX_headerdump(lk_LogState *ls, lk_LogHeader *hs, FILE *fp) {
    struct tm *tm = &hs->tm;
    (void)ls;
    if (hs->tag) fprintf(fp, "[%c][%s][%02d:%02d:%02d][%s]: ", 
            toupper(hs->level[0]), hs->service,
            tm->tm_hour, tm->tm_min, tm->tm_sec, hs->tag);
    else fprintf(fp, "[%c][%s][%02d:%02d:%02d]: ", 
            toupper(hs->level[0]), hs->service,
            tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static void lkX_filedump(lk_LogState *ls, lk_LogHeader *hs, lk_Dumper *dumper) {
    if (dumper->interval > 0 || !dumper->fp)
        lkX_wheelfile(ls, dumper);
    if (dumper->fp) {
        lkX_headerdump(ls, hs, dumper->fp);
        fwrite(hs->msg, 1, hs->msglen, dumper->fp);
        fputc('\n', dumper->fp);
        fflush(dumper->fp);
    }
}

static void lkX_screendump(lk_LogState *ls, const char *s, size_t len, int color)  {
#ifdef _WIN32
    lk_Buffer B;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD attr = 0, reset = FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE;
    DWORD written;
    LPWSTR buff = NULL;
    int bytes, cp = CP_UTF8;
	char eol = '\n';
    if (color & 0x01) attr |= FOREGROUND_RED;
    if (color & 0x02) attr |= FOREGROUND_GREEN;
    if (color & 0x04) attr |= FOREGROUND_BLUE;
    if (color & 0x08) attr |= FOREGROUND_INTENSITY;
    if (color & 0x10) attr |= BACKGROUND_RED;
    if (color & 0x20) attr |= BACKGROUND_GREEN;
    if (color & 0x40) attr |= BACKGROUND_BLUE;
    if (color & 0x80) attr |= BACKGROUND_INTENSITY;
    bytes = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, (int)len, NULL, 0);
    lk_initbuffer(ls->S, &B);
    if (bytes != 0) {
        buff = (LPWSTR)lk_prepbuffsize(&B, bytes * sizeof(WCHAR));
        bytes = MultiByteToWideChar(cp, 0, s, (int)len, buff, bytes);
    }
    SetConsoleTextAttribute(h, attr);
    if (buff) WriteConsoleW(h, buff, bytes, &written, NULL);
    else      WriteConsoleA(h, s, (DWORD)len, &written, NULL);
    SetConsoleTextAttribute(h, reset);
    lk_freebuffer(&B);
	WriteConsoleA(h, &eol, 1, &written, NULL);
#else
    int fg = 30 + (color & 0x7), bg = 40 + ((color & 0x70)>>4);
    (void)ls;
    if (color & 0x08) fg += 60;
    if (color & 0x80) bg += 60;
    fprintf(stdout, "\e[%d;%dm%.*s\e[0m\n", fg, bg, (int)len, s);
	fflush(stdout);
#endif
}

static int lkX_writelog(lk_LogState *ls, const char* service_name, const char* s, size_t len) {
    lk_LogConfig *config;
    lk_LogHeader hs;
    lk_initbuffer(ls->S, &hs.buff);
    lkX_parseheader(&hs, service_name, s, len);
    config = lkX_setconfig(ls, &hs);
    lkX_localtime(time(NULL), &hs.tm);
    if (config->dumper)
        lkX_filedump(ls, &hs, config->dumper);
    if (config->color != 0) {
        lkX_headerdump(ls, &hs, stdout);
        lkX_screendump(ls, hs.msg, hs.msglen, config->color);
    }
    lk_freebuffer(&hs.buff);
    return 0;
}


/* config initialize */

static lk_LogState *lkX_newstate(lk_State *S) {
    lk_LogState *ls = (lk_LogState*)lk_malloc(S, sizeof(lk_LogState));
    lk_LogConfig *config;
    ls->S = S;
    lk_inittable(&ls->config, sizeof(lk_Entry));
    lk_inittable(&ls->dump, sizeof(lk_Entry));
    lk_initpool(&ls->configs, sizeof(lk_LogConfig));
    lk_initpool(&ls->dumpers, sizeof(lk_Dumper));

    /* initialize config */
    lk_resizetable(S, &ls->config, 32);
    config = lkX_newconfig(ls, "info");
    config->color = 0x07;
    config->mask = lk_Mcolor;
    config = lkX_newconfig(ls, "trace");
    config->color = 0x0F;
    config->mask = lk_Mcolor;
    config = lkX_newconfig(ls, "verbose");
    config->color = 0x70;
    config->mask = lk_Mcolor;
    config = lkX_newconfig(ls, "warning");
    config->color = 0x0B;
    config->mask = lk_Mcolor;
    config = lkX_newconfig(ls, "error");
    config->color = 0x9F;
    config->mask = lk_Mcolor;
    config = lkX_newconfig(ls, "default_service");
    lk_strcpy(config->filepath, LK_DEFAULT_LOGPATH, LK_MAX_CONFIGPATH);
    config->interval = 3600;
    config->mask = lk_Mfilepath|lk_Minterval;

    return ls;
}

static void lkX_delstate(lk_LogState* ls) {
    lk_Entry *e = NULL;
    while (lk_nextentry(&ls->config, &e)) {
        lk_LogConfig *config = (lk_LogConfig*)e->key;
        lk_poolfree(&ls->configs, config);
    }
    while (lk_nextentry(&ls->dump, &e)) {
        lk_Dumper *dumper = (lk_Dumper*)e->key;
        if (dumper && dumper->fp) fclose(dumper->fp);
        lk_poolfree(&ls->dumpers, dumper);
    }
    lk_freetable(ls->S, &ls->config);
    lk_freetable(ls->S, &ls->dump);
    lk_freepool(ls->S, &ls->configs);
    lk_freepool(ls->S, &ls->dumpers);
    lk_free(ls->S, ls, sizeof(lk_LogState));
}

static int lkX_update(lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)lk_data(slot);
    lk_Entry *e = NULL;
    (void)S, (void)sig;
    while (lk_nextentry(&ls->config, &e)) {
        lk_LogConfig *config = (lk_LogConfig*)e->key;
        config->mask |= lk_Mreload;
        config->dumper = NULL;
    }
    while (lk_nextentry(&ls->dump, &e)) {
        lk_Dumper *dumper = (lk_Dumper*)e->key;
        if (dumper && dumper->fp) fclose(dumper->fp);
        lk_poolfree(&ls->dumpers, dumper);
        e->key = NULL;
    }
    return LK_OK;
}

static int lkX_launch(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)lk_data(lk_current(S));
    const char *msg = (const char*)sig->data;
    lk_Data *data = lk_newfstring(S, "V[] service '%s'(%p) launched", msg, msg);
    lkX_writelog(ls, (const char*)sender, (const char*)data, lk_len(data));
    lk_deldata(S, data);
    return LK_OK;
}

static int lkX_close(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)lk_data(lk_current(S));
    const char *msg = (const char*)sig->data;
    lk_Data *data = lk_newfstring(S, "V[] service '%s'(%p) closed", msg, msg);
    lkX_writelog(ls, (const char*)sender, (const char*)data, lk_len(data));
    lk_deldata(S, data);
    return LK_OK;
}

LKMOD_API int loki_service_log(lk_State *S, lk_Slot *sender, lk_Signal *sig) {
    lk_LogState *ls = (lk_LogState*)lk_data(lk_current(S));
    if (sender == NULL) {
        ls = lkX_newstate(S);
        lk_setdata(lk_current(S), ls);
        lk_newslot(S, "update", lkX_update, ls);
        lk_newslot(S, "launch", lkX_launch, ls);
        lk_newslot(S, "close", lkX_close, ls);
        return LK_WEAK;
    }
    else if (sig == NULL) {
        const char *msg = (const char*)lk_self(S);
        lk_Data *data = lk_newfstring(S, "V[] service '%s'(%p) closed", msg, msg);
        lkX_writelog(ls, (const char*)sender, (const char*)data, lk_len(data));
        lk_deldata(S, data);
        lkX_delstate(ls);
    }
    else {
        const char *msg = (const char*)sig->data;
        size_t len = sig->isdata ? lk_len((lk_Data*)sig->data) : strlen(msg);
        lkX_writelog(ls, (const char*)sender, msg, len);
    }
    return LK_OK;
}

/* win32cc: flags+='-s -mdll -xc' output='loki.dll' libs+='-lws2_32'
 * unixcc: flags+='-fPIC -shared -xc' output='loki.so'
 * cc: flags+='-Wextra -O3' input='service_*.c lokilib.c' */

