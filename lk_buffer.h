#ifndef lk_buffer_h
#define lk_buffer_h


#include "loki.h"

#define LK_BUFFERSIZE 1024


LK_NS_BEGIN

typedef struct lk_Buffer {
    size_t size;
    size_t capacity;
    lk_State *S;
    char *buff;
    char init_buff[LK_BUFFERSIZE];
} lk_Buffer;

#define lk_buffer(B)      ((B)->buff)
#define lk_buffsize(B)    ((B)->size)
#define lk_resetbuffer(B) ((B)->size = 0)
#define lk_addchar(B,ch)  (*lk_prepbuffsize((B), 1) = (ch), ++(B)->size)
#define lk_addstring(B,s) lk_addlstring((B),(s),strlen(s))

LK_API void lk_initbuffer (lk_State *S, lk_Buffer *b);
LK_API void lk_freebuffer (lk_Buffer *b);

LK_API char *lk_prepbuffsize (lk_Buffer *B, size_t len);

LK_API size_t lk_adddata     (lk_Buffer *B, lk_Data *data);
LK_API size_t lk_addsize     (lk_Buffer *B, int size);
LK_API size_t lk_addlstring  (lk_Buffer *B, const char *s, size_t len);
LK_API size_t lk_addvfstring (lk_Buffer *B, const char *fmt, va_list l);
LK_API size_t lk_addfstring  (lk_Buffer *B, const char *fmt, ...);

LK_API void lk_replacebuffer (lk_Buffer *B, char origch, char newch);

LK_API lk_Data *lk_buffresult (lk_Buffer *B);

LK_NS_END


#endif /* lk_buffer_h */

#if defined(LOKI_IMPLEMENTATION) && !defined(lk_buffer_implemented)
#define lk_buffer_implemented


LK_NS_BEGIN

LK_API void lk_initbuffer (lk_State *S, lk_Buffer *B) {
    B->size = 0;
    B->S = S;
    B->capacity = LK_BUFFERSIZE;
    B->buff = B->init_buff;
}

LK_API void lk_freebuffer (lk_Buffer *B) {
    if (B->buff != B->init_buff)
        lk_free(B->S, B->buff, B->capacity);
    lk_initbuffer(B->S, B);
}

LK_API char *lk_prepbuffsize (lk_Buffer *B, size_t len) {
    if (B->size + len > B->capacity) {
        void *newptr;
        size_t newsize = LK_BUFFERSIZE;
        while (newsize < B->size + len && newsize < ~(size_t)0/2)
            newsize *= 2;
        if (B->buff != B->init_buff)
            newptr = lk_realloc(B->S, B->buff, newsize, B->capacity);
        else {
            newptr = lk_malloc(B->S, newsize);
            memcpy(newptr, B->buff, B->size);
        }
        B->buff = (char*)newptr;
        B->capacity = newsize;
    }
    return &B->buff[B->size];
}

LK_API size_t lk_adddata (lk_Buffer *B, lk_Data *data) {
    size_t len = lk_len(data);
    memcpy(lk_prepbuffsize(B, len), (char*)data, len);
    return B->size += len;
}

LK_API size_t lk_addsize (lk_Buffer *B, int size) {
    size_t capacity = B->capacity;
    if (size < 0 && (size_t)0 - size > B->size)
        return B->size = 0;
    if (size > 0 && B->size + size > capacity) {
        lk_prepbuffsize(B, size);
        memset(B->buff+capacity, 0, B->size+size-capacity);
    }
    return B->size += size;
}

LK_API size_t lk_addlstring (lk_Buffer *B, const char *s, size_t len) {
    memcpy(lk_prepbuffsize(B, len), s, len);
    return B->size += len;
}

LK_API size_t lk_addvfstring (lk_Buffer *B, const char *fmt, va_list l) {
    const size_t init_size = 80;
    char *ptr = lk_prepbuffsize(B, init_size+1);
    va_list l_count;
    int len;
#ifdef va_copy
    va_copy(l_count, l);
#else
    __va_copy(l_count, l);
#endif
    len = lk_vsnprintf(ptr, init_size, fmt, l_count);
    va_end(l_count);
    if (len <= 0) return 0;
    if ((size_t)len > init_size) {
        ptr = lk_prepbuffsize(B, len + 1);
        lk_vsnprintf(ptr, len+1, fmt, l);
    }
    return B->size += len;
}

LK_API size_t lk_addfstring (lk_Buffer *B, const char *fmt, ...) {
    size_t ret;
    va_list l;
    va_start(l, fmt);
    ret = lk_addvfstring(B, fmt, l);
    va_end(l);
    return ret;
}

LK_API void lk_replacebuffer (lk_Buffer *B, char origch, char newch) {
    size_t i;
    for (i = 0; i < B->size; ++i) {
        if (B->buff[i] == origch)
            B->buff[i] = newch;
    }
}

LK_API lk_Data *lk_buffresult (lk_Buffer *B) {
    lk_Data *result = lk_newdata(B->S, B->size+1);
    memcpy(result, B->buff, B->size);
    ((char*)result)[B->size] = '\0';
    lk_setlen(result, B->size);
    lk_freebuffer(B);
    return result;
}

LK_NS_END


#endif /* LOKI_IMPLEMENTATION */

/* win32cc: flags+='-Wextra -s -O3 -mdll -DLOKI_IMPLEMENTATION -std=c90 -pedantic -xc'
 * win32cc: output='loki.dll'
 * unixcc: flags+='-Wextra -s -O3 -fPIC -shared -DLOKI_IMPLEMENTATION -xc'
 * unixcc: output='loki.so' */

