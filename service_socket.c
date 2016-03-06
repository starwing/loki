#define LOKI_MODULE
#include "loki_services.h"

#define ZN_IMPLEMENTATION
#include "znet/znet.h"
#include "znet/znet_buffer.h"


#define lkL_getstate(svr) ((lk_ZNetState*)lk_data(svr))

#define lkL_getpooled(var,type) type *var;  do { \
    lk_lock(zs->lock);                           \
    var = (type*)lk_poolalloc(&zs->var##s);      \
    memset(var, 0, sizeof(*var));                \
    var->zs = zs;                                \
    lk_unlock(zs->lock);                       } while (0)

#define lkL_putpooled(var)                  do { \
    lk_lock(zs->lock);                           \
    lk_poolfree(&zs->var##s, var);               \
    lk_unlock(zs->lock);                       } while (0)

#define lkL_getcached(var,type) type *var;  do { \
    lk_lock(zs->lock);                           \
    if ((var = zs->freed_##var##s) != NULL)      \
        lkL_remove(var);                         \
    else {                                       \
        var = (type*)lk_malloc(zs->S, sizeof(type)); \
        memset(var, 0, sizeof(*var));            \
        var->zs = zs; }                          \
    lkL_insert(&zs->var##s, var);                \
    lk_unlock(zs->lock);                       } while (0)

#define lkL_putcached(var)                  do { \
    lk_lock(zs->lock);                           \
    lkL_remove(var);                             \
    lkL_insert(&zs->freed_##var##s, var);        \
    lk_unlock(zs->lock);                       } while (0)

typedef struct lk_ZNetState {
    lk_Slot *poll;
    lk_State *S;
    zn_State *zs;
    volatile unsigned closing;
    lk_Table handlers;
    lk_MemPool cmds;
    lk_MemPool accepts;
    lk_Tcp *tcps, *freed_tcps;
    lk_Udp *udps, *freed_udps;
    lk_Lock lock; /* lock of freed */
} lk_ZNetState;

typedef struct lk_RecvHandlers {
    lk_HeaderHandler   *on_header;   void *ud_header;
    lk_PacketHandler   *on_packet;   void *ud_packet;
    lk_RecvFromHandler *on_recvfrom; void *ud_recvfrom;
} lk_RecvHandlers;

typedef enum lk_PostCmdType {
    LK_CMD_ACCEPT_DELETE,
    LK_CMD_ACCEPT_LISTEN,
    LK_CMD_TCP_DELETE,
    LK_CMD_TCP_CONNECT,
    LK_CMD_TCP_SEND,
    LK_CMD_TCP_RECV,
    LK_CMD_UDP_BIND,
    LK_CMD_UDP_DELETE,
    LK_CMD_UDP_SENDTO,
    LK_CMD_UDP_RECVFROM,
    LK_CMD_COUNT
} lk_PostCmdType;

typedef struct lk_PostCmd {
    lk_ZNetState *zs;
    lk_Service *service;
    union {
        lk_Accept *accept;
        lk_Tcp *tcp;
        lk_Udp *udp;
    } u;
    union {
        lk_AcceptHandler *on_accept;
        lk_ConnectHandler *on_connect;
        lk_UdpBindHandler *on_udpbind;
    } h;
    void  *data;
    size_t size;
    lk_PostCmdType cmd;
    zn_PeerInfo info;
} lk_PostCmd;

typedef enum lk_SignalType {
    LK_SIGTYPE_ACCEPT_LISTEN,
    LK_SIGTYPE_TCP_CONNECT,
    LK_SIGTYPE_TCP_RECV,
    LK_SIGTYPE_UDP_BIND,
    LK_SIGTYPE_UDP_RECVFROM,
    LK_SIGTYPE_COUNT
} lk_SignalType;

struct lk_Accept {
    lk_ZNetState *zs;
    lk_Service *service;
    lk_AcceptHandler *handler; void *ud;
    zn_Accept *accept;
    lk_Tcp *tcp;
};

struct lk_Tcp {
    lkL_entry(lk_Tcp);
    lk_ZNetState *zs;
    lk_Service *service;
    lk_RecvHandlers *handlers;
    zn_Tcp *tcp;
    void *data;
    zn_SendBuffer send;
    zn_RecvBuffer recv;
    zn_PeerInfo info;
    unsigned session;
    unsigned closing : 1;
};

struct lk_Udp {
    lkL_entry(lk_Udp);
    lk_ZNetState *zs;
    lk_Service *service;
    lk_RecvHandlers *handlers;
    zn_Udp *udp;
    zn_Buffer buff;
    zn_PeerInfo info;
};

static lk_ZNetState *lkL_newstate (lk_State *S) {
    lk_ZNetState *zs = (lk_ZNetState*)lk_malloc(S, sizeof(lk_ZNetState));
    memset(zs, 0, sizeof(*zs));
    zs->S = S;
    zn_initialize();
    if (!lk_initlock(&zs->lock))          goto err_lock;
    if ((zs->zs = zn_newstate()) == NULL) goto err_znet;
    lk_inittable(S, &zs->handlers);
    lk_initmempool(S, &zs->cmds,    sizeof(lk_PostCmd), 0);
    lk_initmempool(S, &zs->accepts, sizeof(lk_Accept),  0);
    return zs;
err_znet:
    lk_freelock(zs->lock);
err_lock:
    lk_free(S, zs);
    lk_discard(S);
    return NULL;
}

static lk_RecvHandlers *lkL_gethandlers(lk_ZNetState *zs, lk_Service *svr) {
    lk_Entry *e;
    lk_RecvHandlers *hs = NULL;
    lk_lock(zs->lock);
    e = lk_getentry(&zs->handlers, (const char*)svr);
    if (e) hs = (lk_RecvHandlers*)e->value;
    lk_unlock(zs->lock);
    return hs;
}

static void lkL_copydata (lk_PostCmd *cmd, const char *buff, size_t size) {
    cmd->data = lk_malloc(cmd->zs->S, size);
    cmd->size = size;
    memcpy(cmd->data, buff, size);
}

static void lkL_copyinfo (lk_PostCmd *cmd, const char *addr, unsigned port) {
    lk_strcpy(cmd->info.addr, addr, ZN_MAX_ADDRLEN);
    cmd->info.port = port;
}

static int lkL_poller (lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_ZNetState *zs = (lk_ZNetState*)ud;
    (void)slot; (void)sig;
    while (!zs->closing)
        zn_run(zs->zs, ZN_RUN_LOOP);
    lk_free(S, zs);
    return LK_OK;
}

static void lkL_postdeletor (void *ud, zn_State *S) {
    lk_ZNetState *zs = (lk_ZNetState*)ud;
    lk_Entry *e = NULL;
    (void)S;
    zs->closing = 1;
    zn_close(zs->zs);
    zn_deinitialize();
    while (lk_nextentry(&zs->handlers, &e))
        lk_free(zs->S, e->value);
    lk_freetable(&zs->handlers, 0);
    lk_freemempool(&zs->cmds);
    lk_freemempool(&zs->accepts);
    lkL_apply(zs->tcps, lk_Tcp, lk_free(zs->S, cur));
    lkL_apply(zs->freed_tcps, lk_Tcp, lk_free(zs->S, cur));
    lkL_apply(zs->udps, lk_Udp, lk_free(zs->S, cur));
    lkL_apply(zs->freed_tcps, lk_Udp, lk_free(zs->S, cur));
}

static int lkL_deletor (lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_ZNetState *zs = (lk_ZNetState*)ud;
    (void)S; (void)slot;
    if (sig == NULL)
        zn_post(zs->zs, lkL_postdeletor, ud);
    return LK_OK;
}


/* post worker */

static zn_RecvHandler     lkL_onrecv;
static zn_RecvFromHandler lkL_onrecvfrom;

static size_t lkL_onheader(void *ud, const char *buff, size_t size) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_RecvHandlers *h = tcp->handlers;
    if (h && h->on_header)
        return h->on_header(tcp->zs->S, h->ud_header, tcp, buff, size);
    return size;
}

static void lkL_onpacket(void *ud, const char *buff, size_t size) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_RecvHandlers *h = tcp->handlers;
    if (h && h->on_packet)
        h->on_packet(tcp->zs->S, h->ud_header, tcp, buff, size);
}

static lk_Tcp *lkL_preparetcp(lk_ZNetState *zs, lk_Service *svr, zn_Tcp *ztcp) {
    int ret;
    lkL_getcached(tcp, lk_Tcp);
    tcp->service = svr;
    tcp->handlers = lkL_gethandlers(zs, svr);
    zn_initrecvbuffer(&tcp->recv);
    zn_initsendbuffer(&tcp->send);
    zn_recvonheader(&tcp->recv, lkL_onheader, tcp);
    zn_recvonpacket(&tcp->recv, lkL_onpacket, tcp);
    ret = zn_recv(ztcp, zn_recvbuff(&tcp->recv), zn_recvsize(&tcp->recv),
            lkL_onrecv, tcp);
    if (ret != ZN_OK) {
        zn_PeerInfo info;
        zn_getpeerinfo(ztcp, &info);
        lk_log(zs->S, "E[recv]" lk_loc("%s (%s:%d)"),
                zn_strerror(ret), info.addr, info.port);
        zn_deltcp(ztcp);
        lkL_putcached(tcp);
        return NULL;
    }
    tcp->tcp = ztcp;
    return tcp;
}

static lk_Udp *lkL_prepareudp(lk_ZNetState *zs, lk_Service *svr, zn_Udp *zudp) {
    int ret;
    lkL_getcached(udp, lk_Udp);
    udp->service = svr;
    udp->handlers = lkL_gethandlers(zs, svr);
    zn_initbuffer(&udp->buff);
    ret = zn_recvfrom(zudp, zn_buffer(&udp->buff), zn_bufflen(&udp->buff),
            lkL_onrecvfrom, udp);
    if (ret != ZN_OK) {
        lk_log(zs->S, "E[recvfrom]" lk_loc("%s"), zn_strerror(ret));
        zn_deludp(zudp);
        lkL_putcached(udp);
        return NULL;
    }
    udp->udp = zudp;
    return udp;
}

static void lkL_deltcp(lk_Tcp *tcp) {
    lk_Signal sig = LK_SIGNAL;
    if (tcp->tcp) {
        zn_deltcp(tcp->tcp);
        zn_resetrecvbuffer(&tcp->recv);
        zn_resetsendbuffer(&tcp->send);
        tcp->tcp = NULL;
    }
    sig.type = LK_SIGTYPE_TCP_RECV;
    sig.session = ZN_ERROR;
    sig.data = tcp;
    lk_emit((lk_Slot*)tcp->service, &sig);
}

static void lkL_accepterror(lk_Accept *accept, unsigned err) {
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_ACCEPT_LISTEN;
    sig.session = err;
    sig.data = accept;
    lk_emit((lk_Slot*)accept->service, &sig);
}

static void lkL_onaccept (void *ud, zn_Accept *zaccept, unsigned err, zn_Tcp *ztcp) {
    lk_Accept *accept = (lk_Accept*)ud;
    lk_ZNetState *zs = accept->zs;
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_ACCEPT_LISTEN;
    sig.data = accept;
    if ((sig.session = err) == ZN_OK
            && (accept->tcp = lkL_preparetcp(zs, accept->service, ztcp)) == NULL)
        return;
    if (err != ZN_OK ||
            (err = zn_accept(zaccept, lkL_onaccept, accept)) != ZN_OK) {
        lk_log(zs->S, "E[accept]" lk_loc("%s"), zn_strerror(err));
        zn_delaccept(zaccept);
        accept->accept = NULL;
    }
    lk_emit((lk_Slot*)accept->service, &sig);
}

static void lkL_onconnect (void *ud, zn_Tcp *ztcp, unsigned err) {
    lk_PostCmd *cmd = (lk_PostCmd*)ud;
    lk_ZNetState *zs = cmd->zs;
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_TCP_CONNECT;
    sig.session = err;
    sig.data = cmd;
    if ((sig.session = err) == ZN_OK) {
        cmd->u.tcp = lkL_preparetcp(zs, cmd->service, ztcp);
        lk_log(zs->S, "I[connect]" lk_loc("%s:%d connected"),
            cmd->info.addr, cmd->info.port);
    }
    else {
        zn_deltcp(ztcp);
        lk_log(zs->S, "E[connect]" lk_loc("%s (%s:%d)"),
                zn_strerror(err), cmd->info.addr, cmd->info.port);
    }
    lk_emit((lk_Slot*)cmd->service, &sig);
}

static void lkL_onrecv (void *ud, zn_Tcp *ztcp, unsigned err, unsigned count) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_ZNetState *zs = tcp->zs;
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_TCP_RECV;
    sig.session = err;
    sig.size = count;
    sig.data = tcp;
    if (err != ZN_OK) {
        lk_log(zs->S, "E[recv]" lk_loc("%s"), zn_strerror(err));   
        zn_deltcp(ztcp);
        tcp->tcp = NULL;
    }
    lk_emit((lk_Slot*)tcp->service, &sig);
}

static void lkL_onsend (void *ud, zn_Tcp *ztcp, unsigned err, unsigned count) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_ZNetState *zs = tcp->zs;
    if (err == ZN_OK) {
        if (zn_sendfinish(&tcp->send, count))
            err = zn_send(tcp->tcp,
                    zn_sendbuff(&tcp->send), zn_sendsize(&tcp->send),
                    lkL_onsend, ud);
        else if (tcp->closing) {
            zn_deltcp(ztcp);
            lkL_putcached(tcp);
        }
    }
    if (err != ZN_OK) {
        lk_log(zs->S, "E[send]" lk_loc("%s"), zn_strerror(err));   
        zn_deltcp(ztcp);
        tcp->tcp = NULL;
    }
}

static void lkL_onrecvfrom (void *ud, zn_Udp *zudp, unsigned err, unsigned count, const char *addr, unsigned port) {
    lk_Udp *udp = (lk_Udp*)ud;
    lk_ZNetState *zs = udp->zs;
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_UDP_RECVFROM;
    sig.session = err;
    sig.size = count;
    sig.data = udp;
    lk_strcpy(udp->info.addr, addr, ZN_MAX_ADDRLEN);
    udp->info.port = port;
    if (err != ZN_OK) {
        lk_log(zs->S, "E[recv]" lk_loc("%s"), zn_strerror(err));
        zn_deludp(zudp);
        udp->udp = NULL;
    }
    lk_emit((lk_Slot*)udp->service, &sig);
}

static void lkL_poster (void *ud, zn_State *S) {
    lk_PostCmd *cmd = (lk_PostCmd*)ud;
    lk_ZNetState *zs = cmd->zs;
    (void)S;
    switch (cmd->cmd) {
    default: break;
    case LK_CMD_ACCEPT_DELETE: {
        lk_Accept *accept = cmd->u.accept;
        if (accept->accept) zn_delaccept(accept->accept);
        lkL_putpooled(accept);
    } break;
    case LK_CMD_TCP_DELETE: {
        lk_Tcp *tcp = cmd->u.tcp;
        if (tcp->tcp) {
            if (zn_bufflen(tcp->send.sending) || zn_bufflen(tcp->send.pending))
                tcp->closing = 1;
            else {
                zn_deltcp(tcp->tcp);
                lkL_putcached(tcp);
            }
        }
    } break;
    case LK_CMD_UDP_DELETE: {
        lk_Udp *udp = cmd->u.udp;
        if (udp->udp) zn_deludp(udp->udp);
        lkL_putcached(udp);
    } break;

    case LK_CMD_ACCEPT_LISTEN: {
        lk_Accept *accept = cmd->u.accept;
        zn_Accept *zaccept = accept->accept;
        int ret;
        if (zaccept) zn_delaccept(zaccept);
        accept->accept = zaccept = zn_newaccept(zs->zs);
        if (zaccept != NULL
                && (ret = zn_listen(zaccept, cmd->info.addr, cmd->info.port)) == ZN_OK
                && (ret = zn_accept(zaccept, lkL_onaccept, accept)) == ZN_OK)
            break;
        lk_log(zs->S, "E[accept]" lk_loc("%s (%s:%d)"),
                zaccept ? zn_strerror(ret) : "can not create zn_Accept",
                cmd->info.addr, cmd->info.port);
        if (zaccept) zn_delaccept(zaccept);
        lkL_accepterror(accept, ZN_ERROR);
    } break;

    case LK_CMD_TCP_CONNECT: {
        zn_Tcp *tcp = zn_newtcp(zs->zs);
        int ret = tcp == NULL ? ZN_ERROR : zn_connect(tcp,
            cmd->info.addr, cmd->info.port, lkL_onconnect, cmd);
        if (ret != ZN_OK) {
            lk_Signal sig = LK_SIGNAL;
            lk_log(zs->S, "E[connect]" lk_loc("%s (%s:%d)"),
                    tcp ? zn_strerror(ret) : "can not create zn_Tcp",
                    cmd->info.addr, cmd->info.port);
            if (tcp) zn_deltcp(tcp);
            sig.type = LK_SIGTYPE_TCP_CONNECT;
            sig.session = ret;
            sig.data = cmd;
            lk_emit((lk_Slot*)cmd->service, &sig);
        }
        return;
    } break;

    case LK_CMD_TCP_SEND: {
        lk_Tcp *tcp = cmd->u.tcp;
        int ret = ZN_OK;
        if (tcp->tcp && zn_sendprepare(&tcp->send, (char*)cmd->data, cmd->size))
            ret = zn_send(tcp->tcp, zn_sendbuff(&tcp->send), zn_sendsize(&tcp->send),
                        lkL_onsend, tcp);
        lk_free(zs->S, cmd->data);
        if (ret != ZN_OK) {
            lk_log(zs->S, "E[send]" lk_loc("%s"), zn_strerror(ret));
            lkL_deltcp(tcp);
        }
    } break;
    case LK_CMD_TCP_RECV: {
        lk_Tcp *tcp = cmd->u.tcp;
        int ret = ZN_OK;
        if (tcp->tcp)
            ret = zn_recv(tcp->tcp,
                zn_recvbuff(&tcp->recv), zn_recvsize(&tcp->recv),
                lkL_onrecv, tcp);
        if (ret != ZN_OK) {
            lk_log(zs->S, "E[recv]" lk_loc("%s"), zn_strerror(ret));
            lkL_deltcp(tcp);
        }
    } break;

    case LK_CMD_UDP_BIND: {
        lk_Signal sig = LK_SIGNAL;
        zn_Udp *zudp = zn_newudp(zs->zs, cmd->info.addr, cmd->info.port);
        if (zudp != NULL)
            cmd->u.udp = lkL_prepareudp(zs, cmd->service, zudp);
        else
            lk_log(zs->S, "E[bindudp]" lk_loc("can not create zn_Udp (%s:%d)"),
                    cmd->info.addr, cmd->info.port);
        sig.type = LK_SIGTYPE_UDP_BIND;
        sig.data = cmd;
        lk_emit((lk_Slot*)cmd->service, &sig);
        return;
    } break;
    case LK_CMD_UDP_SENDTO: {
        lk_Udp *udp = cmd->u.udp;
        int ret = zn_sendto(udp->udp, (char*)cmd->data, cmd->size,
                  cmd->info.addr, cmd->info.port);
        lk_free(zs->S, cmd->data);
        if (ret != ZN_OK) {
            lk_log(zs->S, "W[sendto]" lk_loc("%s"), zn_strerror(ret));
            zn_deludp(udp->udp);
            udp->udp = NULL;
        }
    } break;
    case LK_CMD_UDP_RECVFROM: {
        lk_Udp *udp = cmd->u.udp;
        int ret = zn_recvfrom(udp->udp,
            zn_buffer(&udp->buff), zn_bufflen(&udp->buff),
                lkL_onrecvfrom, udp);
        if (ret != ZN_OK) {
            lk_log(zs->S, "W[recvfrom]" lk_loc("%s"), zn_strerror(ret));
            zn_deludp(udp->udp);
            udp->udp = NULL;
        }
    } break;
    }
    lkL_putpooled(cmd);
}

static void lkL_post (lk_PostCmd *cmd) {
    if (zn_post(cmd->zs->zs, lkL_poster, cmd) != ZN_OK)
        lk_log(cmd->zs->S, "E[socket]" lk_loc("zn_post() error"));
}

static int lkL_refactor (lk_State *S, void *ud, lk_Slot *slot, lk_Signal *sig) {
    lk_ZNetState *zs = (lk_ZNetState*)ud;
    (void)slot;
    switch (sig->type) {
    default: return LK_ERR;

    case LK_SIGTYPE_ACCEPT_LISTEN: {
        lk_Accept *accept = (lk_Accept*)sig->data;
        if (accept->handler)
            accept->handler(S, accept->ud, sig->session, accept, accept->tcp);
        else if (sig->session != ZN_OK) {
            lk_Tcp *tcp = accept->tcp;
            if (tcp) lkL_putcached(tcp);
            lkL_putpooled(accept);
        }
    } break;

    case LK_SIGTYPE_TCP_CONNECT: {
        lk_PostCmd *cmd = (lk_PostCmd*)sig->data;
        if (cmd->h.on_connect)
            cmd->h.on_connect(S, cmd->data, sig->session, cmd->u.tcp);
        else {
            lk_Tcp *tcp = cmd->u.tcp;
            lkL_putcached(tcp);
        }
        lkL_putpooled(cmd);
    } break;

    case LK_SIGTYPE_TCP_RECV: {
        lk_Tcp *tcp = (lk_Tcp*)sig->data;
        if (sig->session != ZN_OK) {
            lk_RecvHandlers *h = tcp->handlers;
            if (h && h->on_header)
                h->on_header(S, h->ud_header, tcp, NULL, 0);
            lkL_putcached(tcp);
        }
        else if (zn_recvfinish(&tcp->recv, sig->size)) {
            lkL_getpooled(cmd, lk_PostCmd);
            cmd->service = lk_self(zs->S);
            cmd->cmd = LK_CMD_TCP_RECV;
            cmd->u.tcp = tcp;
            lkL_post(cmd);
        }
    } break;

    case LK_SIGTYPE_UDP_BIND: {
        lk_PostCmd *cmd = (lk_PostCmd*)sig->data;
        if (cmd->h.on_udpbind)
            cmd->h.on_udpbind(S, cmd->data, sig->session, cmd->u.udp);
        lkL_putpooled(cmd);
    } break;

    case LK_SIGTYPE_UDP_RECVFROM: {
        lk_Udp *udp = (lk_Udp*)sig->data;
        lk_RecvHandlers *h = udp->handlers;
        lkL_getpooled(cmd, lk_PostCmd);
        cmd->service = lk_self(zs->S);
        if (h && h->on_recvfrom)
            h->on_recvfrom(S, h->ud_recvfrom, udp, sig->session,
                zn_buffer(&udp->buff), zn_bufflen(&udp->buff),
                udp->info.addr, udp->info.port);
        cmd->cmd = LK_CMD_UDP_RECVFROM;
        cmd->u.udp = udp;
        lkL_post(cmd); } break;
    }
    return LK_OK;
}


/* interfaces */

LK_API void lk_setonheader (lk_Service *svr, lk_HeaderHandler *h, void *ud) {
    lk_ZNetState *zs = lkL_getstate(svr);
    lk_RecvHandlers *hs;
    lk_Entry *e;
    lk_lock(zs->lock);
    e = lk_setentry(&zs->handlers, (const char*)lk_self(zs->S));
    if (e->value == NULL) {
        e->value = lk_malloc(zs->S, sizeof(lk_RecvHandlers));
        memset(e->value, 0, sizeof(lk_RecvHandlers));
    }
    hs = (lk_RecvHandlers*)e->value;
    hs->on_header = h;
    hs->ud_header = ud;
    lk_unlock(zs->lock);
}

LK_API void lk_setonpacket (lk_Service *svr, lk_PacketHandler *h, void *ud) {
    lk_ZNetState *zs = lkL_getstate(svr);
    lk_RecvHandlers *hs;
    lk_Entry *e;
    lk_lock(zs->lock);
    e = lk_setentry(&zs->handlers, (const char*)svr);
    if (e->value == NULL) {
        e->value = lk_malloc(zs->S, sizeof(lk_RecvHandlers));
        memset(e->value, 0, sizeof(lk_RecvHandlers));
    }
    hs = (lk_RecvHandlers*)e->value;
    hs->on_packet = h;
    hs->ud_packet = ud;
    lk_unlock(zs->lock);
}

LK_API void lk_setonudpmsg (lk_Service *svr, lk_RecvFromHandler *h, void *ud) {
    lk_ZNetState *zs = lkL_getstate(svr);
    lk_RecvHandlers *hs;
    lk_Entry *e;
    lk_lock(zs->lock);
    e = lk_setentry(&zs->handlers, (const char*)svr);
    if (e->value == NULL) {
        e->value = lk_malloc(zs->S, sizeof(lk_RecvHandlers));
        memset(e->value, 0, sizeof(lk_RecvHandlers));
    }
    hs = (lk_RecvHandlers*)e->value;
    hs->on_recvfrom = h;
    hs->ud_recvfrom = ud;
    lk_unlock(zs->lock);
}

LK_API lk_Accept *lk_newaccept (lk_Service *svr, lk_AcceptHandler *h, void *ud) {
    lk_ZNetState *zs = lkL_getstate(svr);
    lkL_getpooled(accept, lk_Accept);
    accept->service = lk_self(zs->S);
    accept->handler = h;
    accept->ud = ud;
    return accept;
}

LK_API void lk_delaccept (lk_Accept *accept) {
    lk_ZNetState *zs = accept->zs;
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_ACCEPT_DELETE;
    cmd->u.accept = accept;
    lkL_post(cmd);
}

LK_API void lk_listen (lk_Accept *accept, const char *addr, unsigned port) {
    lk_ZNetState *zs = accept->zs;
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_ACCEPT_LISTEN;
    cmd->u.accept = accept;
    lkL_copyinfo(cmd, addr, port);
    lkL_post(cmd);
}

LK_API void lk_connect (lk_Service *svr, const char *addr, unsigned port, lk_ConnectHandler *h, void *ud) {
    lk_ZNetState *zs = lkL_getstate(svr);
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_TCP_CONNECT;
    cmd->h.on_connect = h;
    cmd->data = ud;
    lkL_copyinfo(cmd, addr, port);
    lkL_post(cmd);
}

LK_API void *lk_gettcpdata(lk_Tcp *tcp) {
    lk_ZNetState *zs = tcp->zs;
    void *data;
    lk_lock(zs->lock);
    data = tcp->data;
    lk_unlock(zs->lock);
    return data;
}

LK_API void lk_settcpdata(lk_Tcp *tcp, void *data) {
    lk_ZNetState *zs = tcp->zs;
    lk_lock(zs->lock);
    tcp->data = data;
    lk_unlock(zs->lock);
}


LK_API void lk_deltcp (lk_Tcp *tcp) {
    lk_ZNetState *zs = tcp->zs;
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_TCP_DELETE;
    cmd->u.tcp = tcp;
    lkL_post(cmd);
}

LK_API void lk_send (lk_Tcp *tcp, const char *buff, unsigned size) {
    lk_ZNetState *zs = tcp->zs;
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_TCP_SEND;
    cmd->u.tcp = tcp;
    lkL_copydata(cmd, buff, size);
    lkL_post(cmd);
}

LK_API void lk_bindudp (lk_Service *svr, const char *addr, unsigned port, lk_UdpBindHandler *h, void *ud) {
    lk_ZNetState *zs = lkL_getstate(svr);
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_UDP_BIND;
    cmd->h.on_udpbind = h;
    cmd->data = ud;
    lkL_copyinfo(cmd, addr, port);
    lkL_post(cmd);
}

LK_API void lk_deludp (lk_Udp *udp) {
    lk_ZNetState *zs = udp->zs;
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_UDP_DELETE;
    cmd->u.udp = udp;
    lkL_post(cmd);
}

LK_API void lk_sendto (lk_Udp *udp, const char *buff, unsigned size, const char *addr, unsigned port) {
    lk_ZNetState *zs = udp->zs;
    lkL_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_UDP_SENDTO;
    cmd->u.udp = udp;
    lkL_copydata(cmd, buff, size);
    lkL_copyinfo(cmd, addr, port);
    lkL_post(cmd);
}


/* entry point */

LKMOD_API int loki_service_socket (lk_State *S) {
    lk_ZNetState *zs = lkL_newstate(S);
    lk_Service *svr = lk_self(S);
    lk_setdata(S, zs);
    zs->poll = lk_newpoll(S, "poll", lkL_poller, zs);
    lk_setslothandler((lk_Slot*)svr, lkL_deletor, zs);
    lk_setrefactor(S, lkL_refactor, zs);
    return LK_WEAK;
}

/* win32cc: flags+='-s -O3 -mdll'
 * win32cc: input='lokilib.c service_*.c' output='loki.dll' libs+='-lws2_32'
 * unixcc: flags+='-Wextra -s -O3 -fPIC -shared -DLOKI_IMPLEMENTATION'
 * unixcc: output='loki.so' */

