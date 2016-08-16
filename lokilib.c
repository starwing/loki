#define LOKI_IMPLEMENTATION
#include "loki_services.h"

/* win32cc: flags+='-s -mdll -xc' output='loki.dll' libs+='-lws2_32'
 * unixcc: flags+='-fPIC -shared -xc' output='loki.so'
 * cc: flags+='-Wextra -O3' input='service_*.c lokilib.c' */

