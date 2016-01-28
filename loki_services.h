#ifndef loki_services_h
#define loki_services_h


#include "loki.h"


#ifndef lk_Time
# ifdef LOKI_USE_64BIT_TIMER
typedef unsigned long long lk_Time;
# else
typedef unsigned lk_Time;
# endif
# define lk_Time lk_Time
#endif /* lk_Time */

typedef struct lk_Timer lk_Timer;

typedef lk_Time lk_TimerHandler (lk_State *S, void *ud, lk_Timer *timer, lk_Time delayed);


LK_API int lk_openlibs(lk_State *S);


/* timer service */

LKMOD_API int loki_service_timer(lk_State *S);

LK_API lk_Time lk_time(void);

LK_API lk_Timer *lk_newtimer (lk_Service *svr, lk_TimerHandler *h, void *ud);
LK_API void      lk_deltimer (lk_Timer *timer);

LK_API void lk_starttimer  (lk_Timer *timer, lk_Time delayms);
LK_API void lk_canceltimer (lk_Timer *timer);


/* socket service */

LKMOD_API int loki_service_socket(lk_State *S);

typedef struct lk_Accept lk_Accept;
typedef struct lk_Tcp    lk_Tcp;
typedef struct lk_Udp    lk_Udp;

typedef void lk_TcpHandler (lk_State *S, void *ud, unsigned err, lk_Tcp *tcp);
typedef void lk_UdpHandler (lk_State *S, void *ud, unsigned err, lk_Udp *udp);

typedef size_t lk_HeaderHandler   (lk_State *S, void *ud, lk_Tcp *tcp, const char *buff, size_t len);
typedef void   lk_PacketHandler   (lk_State *S, void *ud, lk_Tcp *tcp, const char *buff, size_t len);
typedef void   lk_RecvFromHandler (lk_State *S, void *ud, lk_Udp *udp, unsigned err,
                                   const char *buff, unsigned count,
                                   const char *addr, unsigned port);

LK_API void lk_setonheader (lk_Service *svr, lk_HeaderHandler *h, void *ud);
LK_API void lk_setonpacket (lk_Service *svr, lk_PacketHandler *h, void *ud);
LK_API void lk_setonudpmsg (lk_Service *svr, lk_RecvFromHandler *h, void *ud);

LK_API lk_Accept *lk_newaccept (lk_Service *svr, lk_TcpHandler *h, void *ud);
LK_API void       lk_delaccept (lk_Accept *accept);

LK_API void lk_listen (lk_Accept *accept, const char *addr, unsigned port);

LK_API void lk_connect (lk_Service *svr, const char *addr, unsigned port,
                        lk_TcpHandler *h, void *ud);
LK_API void lk_deltcp  (lk_Tcp *tcp);

LK_API unsigned lk_getsession (lk_Tcp *tcp);
LK_API void     lk_setsession (lk_Tcp *tcp, unsigned session);

LK_API void lk_send (lk_Tcp *tcp, const char *buff, unsigned size);

LK_API void lk_bindudp (lk_Service *svr, const char *addr, unsigned port,
                        lk_UdpHandler *h, void *ud);
LK_API void lk_deludp  (lk_Udp *udp);

LK_API void lk_sendto (lk_Udp *udp, const char *buff, unsigned len,
                       const char *addr, unsigned port);


#endif /* loki_services_h */

#if defined(LOKI_IMPLEMENTATION) && !defined(loki_services_implemented)
#define loki_services_implemented

LK_API int lk_openlibs(lk_State *S) {
    lk_preload(S, "timer",  loki_service_timer);
    lk_preload(S, "socket", loki_service_socket);
    return LK_OK;
}


#endif
