#define LOKI_MODULE
#include "loki_services.h"

#define ZN_IMPLEMENTATION
#include "znet/znet.h"
#include "znet/zn_buffer.h"


#define lkX_getstate(svr) ((lk_ZNetState*)lk_data((lk_Slot*)svr))

#define lkX_getpooled(var,type) type *var;  do { \
    lk_lock(zs->lock);                           \
    var = (type*)lk_poolalloc(zs->S, &zs->var##s);\
    memset(var, 0, sizeof(*var));                \
    var->zs = zs;                                \
    lk_unlock(zs->lock);                       } while (0)

#define lkX_putpooled(var)                  do { \
    lk_lock(zs->lock);                           \
    lk_poolfree(&zs->var##s, var);               \
    lk_unlock(zs->lock);                       } while (0)

#define lkX_getcached(var,type) type *var;  do { \
    lk_lock(zs->lock);                           \
    if ((var = zs->freed_##var##s) != NULL)      \
        znL_remove(var);                         \
    else {                                       \
        var = (type*)lk_malloc(zs->S, sizeof(type)); \
        memset(var, 0, sizeof(*var));            \
        var->zs = zs; }                          \
    znL_insert(&zs->var##s, var);                \
    lk_unlock(zs->lock);                       } while (0)

#define lkX_putcached(var)                  do { \
    lk_lock(zs->lock);                           \
    znL_remove(var);                             \
    znL_insert(&zs->freed_##var##s, var);        \
    lk_unlock(zs->lock);                       } while (0)

typedef struct lk_ZNetState {
    lk_Slot *poll;
    lk_State *S;
    zn_State *zs;
    volatile unsigned closing;
    lk_Table hmap;
    lk_MemPool cmds;
    lk_MemPool accepts;
    lk_MemPool handlers;
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
    lk_Service   *service;
    void         *data;
    union {
        lk_Accept *accept;
        lk_Tcp    *tcp;
        lk_Udp    *udp;
    } u;
    union {
        lk_AcceptHandler  *on_accept;
        lk_ConnectHandler *on_connect;
        lk_UdpBindHandler *on_udpbind;
    } h;
    lk_PostCmdType cmd;
    zn_PeerInfo    info;
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
    znL_entry(lk_Tcp);
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
    znL_entry(lk_Udp);
    lk_ZNetState *zs;
    lk_Service *service;
    lk_RecvHandlers *handlers;
    zn_Udp *udp;
    zn_Buffer buff;
    zn_PeerInfo info;
};

typedef struct lk_HandlersEntry {
    lk_Entry entry;
    lk_RecvHandlers *handlers;
} lk_HandlersEntry;

static lk_ZNetState *lkX_newstate (lk_State *S) {
    lk_ZNetState *zs = (lk_ZNetState*)lk_malloc(S, sizeof(lk_ZNetState));
    memset(zs, 0, sizeof(*zs));
    zs->S = S;
    zn_initialize();
    if (!lk_initlock(&zs->lock))          goto err_lock;
    if ((zs->zs = zn_newstate()) == NULL) goto err_znet;
    lk_inittable(&zs->hmap, sizeof(lk_HandlersEntry));
    lk_initpool(&zs->cmds,    sizeof(lk_PostCmd));
    lk_initpool(&zs->accepts, sizeof(lk_Accept));
    lk_initpool(&zs->handlers, sizeof(lk_RecvHandlers));
    return zs;
err_znet:
    lk_freelock(zs->lock);
err_lock:
    lk_free(S, zs, sizeof(lk_ZNetState));
    lk_discard(S);
    return NULL;
}

static lk_RecvHandlers *lkX_gethandlers(lk_ZNetState *zs, lk_Service *svr) {
    lk_HandlersEntry *e;
    lk_RecvHandlers *hs = NULL;
    lk_lock(zs->lock);
    e = (lk_HandlersEntry*)lk_gettable(&zs->hmap, (const char*)svr);
    if (e) hs = (lk_RecvHandlers*)e->handlers;
    lk_unlock(zs->lock);
    return hs;
}

static void lkX_copyinfo (lk_PostCmd *cmd, const char *addr, unsigned port) {
    lk_strcpy(cmd->info.addr, addr, ZN_MAX_ADDRLEN);
    cmd->info.port = port;
}

static int lkX_poller (lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    lk_ZNetState *zs = lkX_getstate(slot);
    (void)slot, (void)sig;
    while (!zs->closing)
        zn_run(zs->zs, ZN_RUN_LOOP);
    lk_free(S, zs, sizeof(lk_ZNetState));
    return LK_OK;
}

static void lkX_postdeletor (void *ud, zn_State *S) {
    lk_ZNetState *zs = (lk_ZNetState*)ud;
    (void)S;
    zs->closing = 1;
    zn_close(zs->zs);
    zn_deinitialize();
    lk_freetable(zs->S, &zs->hmap);
    lk_freepool(zs->S, &zs->cmds);
    lk_freepool(zs->S, &zs->accepts);
    lk_freepool(zs->S, &zs->handlers);
    znL_apply(lk_Tcp, &zs->tcps, lk_free(zs->S, cur, sizeof(lk_Tcp)));
    znL_apply(lk_Tcp, &zs->freed_tcps, lk_free(zs->S, cur, sizeof(lk_Tcp)));
    znL_apply(lk_Udp, &zs->udps, lk_free(zs->S, cur, sizeof(lk_Udp)));
    znL_apply(lk_Udp, &zs->freed_udps, lk_free(zs->S, cur, sizeof(lk_Udp)));
}


/* post worker */

static zn_RecvHandler     lkX_onrecv;
static zn_RecvFromHandler lkX_onrecvfrom;

static size_t lkX_onheader(void *ud, const char *buff, size_t size) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_RecvHandlers *h = tcp->handlers;
    if (h && h->on_header)
        return h->on_header(tcp->zs->S, h->ud_header, tcp, buff, size);
    return size;
}

static void lkX_onpacket(void *ud, const char *buff, size_t size) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_RecvHandlers *h = tcp->handlers;
    if (h && h->on_packet)
        h->on_packet(tcp->zs->S, h->ud_header, tcp, buff, size);
}

static lk_Tcp *lkX_preparetcp(lk_ZNetState *zs, lk_Service *svr, zn_Tcp *ztcp) {
    int ret;
    lkX_getcached(tcp, lk_Tcp);
    tcp->service = svr;
    tcp->handlers = lkX_gethandlers(zs, svr);
    zn_initrecvbuffer(&tcp->recv);
    zn_initsendbuffer(&tcp->send);
    zn_recvonheader(&tcp->recv, lkX_onheader, tcp);
    zn_recvonpacket(&tcp->recv, lkX_onpacket, tcp);
    ret = zn_recv(ztcp, zn_recvbuff(&tcp->recv), zn_recvsize(&tcp->recv),
            lkX_onrecv, tcp);
    if (ret != ZN_OK) {
        zn_PeerInfo info;
        zn_getpeerinfo(ztcp, &info);
        lk_log(zs->S, "E[recv]" lk_loc("[%p] %s (%s:%d)"),
                tcp, zn_strerror(ret), info.addr, info.port);
        zn_deltcp(ztcp);
        lkX_putcached(tcp);
        return NULL;
    }
    tcp->tcp = ztcp;
    return tcp;
}

static lk_Udp *lkX_prepareudp(lk_ZNetState *zs, lk_Service *svr, zn_Udp *zudp) {
    int ret;
    lkX_getcached(udp, lk_Udp);
    udp->service = svr;
    udp->handlers = lkX_gethandlers(zs, svr);
    zn_initbuffer(&udp->buff);
    ret = zn_recvfrom(zudp, zn_buffer(&udp->buff), zn_bufflen(&udp->buff),
            lkX_onrecvfrom, udp);
    if (ret != ZN_OK) {
        lk_log(zs->S, "E[recvfrom]" lk_loc("[%p] %s"), udp, zn_strerror(ret));
        zn_deludp(zudp);
        lkX_putcached(udp);
        return NULL;
    }
    udp->udp = zudp;
    return udp;
}

static void lkX_deltcp(lk_Tcp *tcp) {
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

static void lkX_accepterror(lk_Accept *accept, unsigned err) {
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_ACCEPT_LISTEN;
    sig.session = err;
    sig.data = accept;
    lk_emit((lk_Slot*)accept->service, &sig);
}

static void lkX_onaccept (void *ud, zn_Accept *zaccept, unsigned err, zn_Tcp *ztcp) {
    lk_Accept *accept = (lk_Accept*)ud;
    lk_ZNetState *zs = accept->zs;
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_ACCEPT_LISTEN;
    sig.data = accept;
    if ((sig.session = err) == ZN_OK && (accept->tcp =
                lkX_preparetcp(zs, accept->service, ztcp)) == NULL)
        return;
    if (err == ZN_OK &&
            (err = zn_accept(zaccept, lkX_onaccept, accept)) == ZN_OK)
        lk_log(zs->S, "I[accept]" lk_loc("[%p][%p] new connection accepted"),
                accept, accept->tcp);
    else {
        lk_log(zs->S, "E[accept]" lk_loc("[%p] %s"), accept, zn_strerror(err));
        zn_delaccept(zaccept);
        accept->accept = NULL;
    }
    lk_emit((lk_Slot*)accept->service, &sig);
}

static void lkX_onconnect (void *ud, zn_Tcp *ztcp, unsigned err) {
    lk_PostCmd *cmd = (lk_PostCmd*)ud;
    lk_ZNetState *zs = cmd->zs;
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_TCP_CONNECT;
    sig.session = err;
    sig.data = cmd;
    if ((sig.session = err) == ZN_OK) {
        cmd->u.tcp = lkX_preparetcp(zs, cmd->service, ztcp);
        lk_log(zs->S, "I[connect]" lk_loc("[%p] %s:%d connected"),
                cmd->u.tcp, cmd->info.addr, cmd->info.port);
    }
    else {
        zn_deltcp(ztcp);
        lk_log(zs->S, "E[connect]" lk_loc("[%p] %s (%s:%d)"),
                cmd->u.tcp, zn_strerror(err), cmd->info.addr, cmd->info.port);
    }
    lk_emit((lk_Slot*)cmd->service, &sig);
}

static void lkX_onrecv (void *ud, zn_Tcp *ztcp, unsigned err, unsigned count) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_ZNetState *zs = tcp->zs;
    lk_Signal sig = LK_SIGNAL;
    sig.type = LK_SIGTYPE_TCP_RECV;
    sig.session = err;
    sig.size = count;
    sig.data = tcp;
    if (err != ZN_OK) {
        lk_log(zs->S, "E[recv]" lk_loc("[%p] %s"), tcp, zn_strerror(err));
        zn_deltcp(ztcp);
        tcp->tcp = NULL;
    }
    lk_emit((lk_Slot*)tcp->service, &sig);
}

static void lkX_onsend (void *ud, zn_Tcp *ztcp, unsigned err, unsigned count) {
    lk_Tcp *tcp = (lk_Tcp*)ud;
    lk_ZNetState *zs = tcp->zs;
    if (err == ZN_OK) {
        if (zn_sendfinish(&tcp->send, count))
            err = zn_send(tcp->tcp,
                    zn_sendbuff(&tcp->send), zn_sendsize(&tcp->send),
                    lkX_onsend, ud);
        else if (tcp->closing) {
            lk_log(zs->S, "I[close]" lk_loc("[%p] tcp closed"), tcp);
            zn_deltcp(ztcp);
            lkX_putcached(tcp);
        }
    }
    if (err != ZN_OK) {
        lk_log(zs->S, "E[send]" lk_loc("[%p] %s"), tcp, zn_strerror(err));
        zn_deltcp(ztcp);
        tcp->tcp = NULL;
    }
}

static void lkX_onrecvfrom (void *ud, zn_Udp *zudp, unsigned err, unsigned count, const char *addr, unsigned port) {
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
        lk_log(zs->S, "E[recvfrom]" lk_loc("[%p] %s"), udp, zn_strerror(err));
        zn_deludp(zudp);
        udp->udp = NULL;
    }
    lk_emit((lk_Slot*)udp->service, &sig);
}

static void lkX_poster (void *ud, zn_State *S) {
    lk_PostCmd *cmd = (lk_PostCmd*)ud;
    lk_ZNetState *zs = cmd->zs;
    (void)S;
    switch (cmd->cmd) {
    default: break;
    case LK_CMD_ACCEPT_DELETE: {
        lk_Accept *accept = cmd->u.accept;
        if (accept->accept) zn_delaccept(accept->accept);
        lk_log(zs->S, "I[close]" lk_loc("[%p] accept closed"), accept);
        lkX_putpooled(accept);
    } break;
    case LK_CMD_TCP_DELETE: {
        lk_Tcp *tcp = cmd->u.tcp;
        if (tcp->tcp) {
            if (zn_bufflen(tcp->send.sending) || zn_bufflen(tcp->send.pending))
                tcp->closing = 1;
            else {
                lk_log(zs->S, "I[close]" lk_loc("[%p] tcp closed"), tcp);
                zn_deltcp(tcp->tcp);
                lkX_putcached(tcp);
            }
        }
    } break;
    case LK_CMD_UDP_DELETE: {
        lk_Udp *udp = cmd->u.udp;
        if (udp->udp) zn_deludp(udp->udp);
        lk_log(zs->S, "I[close]" lk_loc("[%p] udp closed"), udp);
        lkX_putcached(udp);
    } break;
    case LK_CMD_ACCEPT_LISTEN: {
        lk_Accept *accept = cmd->u.accept;
        zn_Accept *zaccept = accept->accept;
        int ret;
        if (zaccept) zn_delaccept(zaccept);
        accept->accept = zaccept = zn_newaccept(zs->zs);
        if (zaccept != NULL
                && (ret = zn_listen(zaccept, cmd->info.addr, cmd->info.port)) == ZN_OK
                && (ret = zn_accept(zaccept, lkX_onaccept, accept)) == ZN_OK)
            lk_log(zs->S, "I[listen]" lk_loc("[%p] listen (%s:%d)"),
                    accept, cmd->info.addr, cmd->info.port);
        else {
            lk_log(zs->S, "E[listen]" lk_loc("[%p] %s (%s:%d)"),
                    accept, zaccept ? zn_strerror(ret) : "can not create zn_Accept",
                    cmd->info.addr, cmd->info.port);
            if (zaccept) zn_delaccept(zaccept);
            lkX_accepterror(accept, ZN_ERROR);
        }
    } break;
    case LK_CMD_TCP_CONNECT: {
        zn_Tcp *tcp = zn_newtcp(zs->zs);
        int ret = tcp == NULL ? ZN_ERROR : zn_connect(tcp,
            cmd->info.addr, cmd->info.port, lkX_onconnect, cmd);
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
        size_t size = lk_len((lk_Data*)cmd->data);
        if (tcp->tcp && zn_sendprepare(&tcp->send, (char*)cmd->data, size))
            ret = zn_send(tcp->tcp, zn_sendbuff(&tcp->send), zn_sendsize(&tcp->send),
                        lkX_onsend, tcp);
        lk_deldata(zs->S, (lk_Data*)cmd->data);
        if (ret != ZN_OK) {
            lk_log(zs->S, "E[send]" lk_loc("[%p] %s"), tcp, zn_strerror(ret));
            lkX_deltcp(tcp);
        }
    } break;
    case LK_CMD_TCP_RECV: {
        lk_Tcp *tcp = cmd->u.tcp;
        int ret = ZN_OK;
        if (tcp->tcp)
            ret = zn_recv(tcp->tcp,
                zn_recvbuff(&tcp->recv), zn_recvsize(&tcp->recv),
                lkX_onrecv, tcp);
        if (ret != ZN_OK) {
            lk_log(zs->S, "E[recv]" lk_loc("[%p] %s"), tcp, zn_strerror(ret));
            lkX_deltcp(tcp);
        }
    } break;
    case LK_CMD_UDP_BIND: {
        lk_Signal sig = LK_SIGNAL;
        zn_Udp *zudp = zn_newudp(zs->zs, cmd->info.addr, cmd->info.port);
        if (zudp != NULL)
            cmd->u.udp = lkX_prepareudp(zs, cmd->service, zudp);
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
        size_t size = lk_len((lk_Data*)cmd->data);
        int ret = zn_sendto(udp->udp, (char*)cmd->data, size,
                  cmd->info.addr, cmd->info.port);
        lk_deldata(zs->S, (lk_Data*)cmd->data);
        if (ret != ZN_OK) {
            lk_log(zs->S, "W[sendto]" lk_loc("[%p] %s"), udp, zn_strerror(ret));
            zn_deludp(udp->udp);
            udp->udp = NULL;
        }
    } break;
    case LK_CMD_UDP_RECVFROM: {
        lk_Udp *udp = cmd->u.udp;
        int ret = zn_recvfrom(udp->udp,
            zn_buffer(&udp->buff), zn_bufflen(&udp->buff),
                lkX_onrecvfrom, udp);
        if (ret != ZN_OK) {
            lk_log(zs->S, "W[recvfrom]" lk_loc("[%p] %s"), udp, zn_strerror(ret));
            zn_deludp(udp->udp);
            udp->udp = NULL;
        }
    } break;
    }
    lkX_putpooled(cmd);
}

static void lkX_post (lk_PostCmd *cmd) {
    if (zn_post(cmd->zs->zs, lkX_poster, cmd) != ZN_OK)
        lk_log(cmd->zs->S, "E[socket]" lk_loc("zn_post() error"));
}

static int lkX_refactor (lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    lk_ZNetState *zs = lkX_getstate((lk_Slot*)sig->src);
    (void)slot;
    switch (sig->type) {
    default: return LK_ERR;

    case LK_SIGTYPE_ACCEPT_LISTEN: {
        lk_Accept *accept = (lk_Accept*)sig->data;
        if (accept->handler)
            accept->handler(S, accept->ud, sig->session, accept, accept->tcp);
        else if (sig->session != ZN_OK) {
            lk_Tcp *tcp = accept->tcp;
            if (tcp) lkX_putcached(tcp);
            lkX_putpooled(accept);
        }
    } break;

    case LK_SIGTYPE_TCP_CONNECT: {
        lk_PostCmd *cmd = (lk_PostCmd*)sig->data;
        if (cmd->h.on_connect)
            cmd->h.on_connect(S, cmd->data, sig->session, cmd->u.tcp);
        else {
            lk_Tcp *tcp = cmd->u.tcp;
            lkX_putcached(tcp);
        }
        lkX_putpooled(cmd);
    } break;

    case LK_SIGTYPE_TCP_RECV: {
        lk_Tcp *tcp = (lk_Tcp*)sig->data;
        if (sig->session != ZN_OK) {
            lk_RecvHandlers *h = tcp->handlers;
            if (h && h->on_header)
                h->on_header(S, h->ud_header, tcp, NULL, 0);
            lkX_putcached(tcp);
        }
        else if (zn_recvfinish(&tcp->recv, sig->size)) {
            lkX_getpooled(cmd, lk_PostCmd);
            cmd->service = lk_self(zs->S);
            cmd->cmd = LK_CMD_TCP_RECV;
            cmd->u.tcp = tcp;
            lkX_post(cmd);
        }
    } break;

    case LK_SIGTYPE_UDP_BIND: {
        lk_PostCmd *cmd = (lk_PostCmd*)sig->data;
        if (cmd->h.on_udpbind)
            cmd->h.on_udpbind(S, cmd->data, sig->session, cmd->u.udp);
        lkX_putpooled(cmd);
    } break;

    case LK_SIGTYPE_UDP_RECVFROM: {
        lk_Udp *udp = (lk_Udp*)sig->data;
        lk_RecvHandlers *h = udp->handlers;
        lkX_getpooled(cmd, lk_PostCmd);
        cmd->service = lk_self(zs->S);
        if (h && h->on_recvfrom)
            h->on_recvfrom(S, h->ud_recvfrom, udp, sig->session,
                zn_buffer(&udp->buff), zn_bufflen(&udp->buff),
                udp->info.addr, udp->info.port);
        cmd->cmd = LK_CMD_UDP_RECVFROM;
        cmd->u.udp = udp;
        lkX_post(cmd); } break;
    }
    return LK_OK;
}


/* interfaces */

static lk_RecvHandlers *lkX_sethandlers (lk_ZNetState *zs) {
    lk_HandlersEntry *e =
        (lk_HandlersEntry*)lk_settable(zs->S, &zs->hmap, (const char*)lk_self(zs->S));
    if (e->handlers == NULL) {
        e->handlers = (lk_RecvHandlers*)lk_poolalloc(zs->S, &zs->handlers);
        memset(e->handlers, 0, sizeof(lk_RecvHandlers));
    }
    return e->handlers;
}

LK_API void lk_setonheader (lk_Service *svr, lk_HeaderHandler *h, void *ud) {
    lk_ZNetState *zs = lkX_getstate(svr);
    lk_RecvHandlers *hs;
    lk_lock(zs->lock);
    hs = lkX_sethandlers(zs);
    hs->on_header = h;
    hs->ud_header = ud;
    lk_unlock(zs->lock);
}

LK_API void lk_setonpacket (lk_Service *svr, lk_PacketHandler *h, void *ud) {
    lk_ZNetState *zs = lkX_getstate(svr);
    lk_RecvHandlers *hs;
    lk_lock(zs->lock);
    hs = lkX_sethandlers(zs);
    hs->on_packet = h;
    hs->ud_packet = ud;
    lk_unlock(zs->lock);
}

LK_API void lk_setonudpmsg (lk_Service *svr, lk_RecvFromHandler *h, void *ud) {
    lk_ZNetState *zs = lkX_getstate(svr);
    lk_RecvHandlers *hs;
    lk_lock(zs->lock);
    hs = lkX_sethandlers(zs);
    hs->on_recvfrom = h;
    hs->ud_recvfrom = ud;
    lk_unlock(zs->lock);
}

LK_API lk_Accept *lk_newaccept (lk_Service *svr, lk_AcceptHandler *h, void *ud) {
    lk_ZNetState *zs = lkX_getstate(svr);
    lkX_getpooled(accept, lk_Accept);
    accept->service = lk_self(zs->S);
    accept->handler = h;
    accept->ud = ud;
    return accept;
}

LK_API void lk_delaccept (lk_Accept *accept) {
    lk_ZNetState *zs = accept->zs;
    lkX_getpooled(cmd, lk_PostCmd);
    accept->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_ACCEPT_DELETE;
    cmd->u.accept = accept;
    lkX_post(cmd);
}

LK_API void lk_listen (lk_Accept *accept, const char *addr, unsigned port) {
    lk_ZNetState *zs = accept->zs;
    lkX_getpooled(cmd, lk_PostCmd);
    accept->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_ACCEPT_LISTEN;
    cmd->u.accept = accept;
    lkX_copyinfo(cmd, addr, port);
    lkX_post(cmd);
}

LK_API void lk_connect (lk_Service *svr, const char *addr, unsigned port, lk_ConnectHandler *h, void *ud) {
    lk_ZNetState *zs = lkX_getstate(svr);
    lkX_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_TCP_CONNECT;
    cmd->h.on_connect = h;
    cmd->data = ud;
    lkX_copyinfo(cmd, addr, port);
    lkX_post(cmd);
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
    lkX_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_TCP_DELETE;
    cmd->u.tcp = tcp;
    lkX_post(cmd);
}

LK_API void lk_send (lk_Tcp *tcp, const char *buff, unsigned size) {
    lk_ZNetState *zs = tcp->zs;
    lkX_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_TCP_SEND;
    cmd->u.tcp = tcp;
    cmd->data = lk_newlstring(zs->S, buff, size);
    lkX_post(cmd);
}

LK_API void lk_bindudp (lk_Service *svr, const char *addr, unsigned port, lk_UdpBindHandler *h, void *ud) {
    lk_ZNetState *zs = lkX_getstate(svr);
    lkX_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_UDP_BIND;
    cmd->h.on_udpbind = h;
    cmd->data = ud;
    lkX_copyinfo(cmd, addr, port);
    lkX_post(cmd);
}

LK_API void lk_deludp (lk_Udp *udp) {
    lk_ZNetState *zs = udp->zs;
    lkX_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_UDP_DELETE;
    cmd->u.udp = udp;
    lkX_post(cmd);
}

LK_API void lk_sendto (lk_Udp *udp, const char *buff, unsigned size, const char *addr, unsigned port) {
    lk_ZNetState *zs = udp->zs;
    lkX_getpooled(cmd, lk_PostCmd);
    cmd->service = lk_self(zs->S);
    cmd->cmd = LK_CMD_UDP_SENDTO;
    cmd->u.udp = udp;
    cmd->data = lk_newlstring(zs->S, buff, size);
    lkX_copyinfo(cmd, addr, port);
    lkX_post(cmd);
}


/* entry point */

LKMOD_API int loki_service_socket (lk_State *S, lk_Slot *slot, lk_Signal *sig) {
    if (slot == NULL) {
        lk_ZNetState *zs = lkX_newstate(S);
        lk_Service *svr = lk_self(S);
        zs->poll = lk_newpoll(S, "poll", lkX_poller, zs);
        lk_setrefactor(svr, lkX_refactor);
        lk_setdata((lk_Slot*)svr, zs);
        return LK_WEAK;
    }
    else if (sig == NULL) {
        lk_ZNetState *zs = lkX_getstate(slot);
        zn_post(zs->zs, lkX_postdeletor, zs);
    }
    return LK_OK;
}

/* win32cc: flags+='-s -mdll -xc' output='loki.dll' libs+='-lws2_32'
 * unixcc: flags+='-fPIC -shared -xc' output='loki.so'
 * cc: flags+='-Wextra -O3' input='service_*.c lokilib.c' */

