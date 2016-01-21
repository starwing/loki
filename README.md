loki - one-header online game framework
----------------------------------------

loki is a online game framework, inspired by cloudwu's
[skynet](https://github.com/cloudwu/skynet).

loki is not only used in online game server, but more. It's a multi-thread
service signal/slot system. Every service register it's own slots, and receive
message to offer service. 

loki only have one header as it's core. To define loki functions (only allow
in only **one** C file, define `LOKI_IMPLEMENTATION` before include `loki.h`.
loki also has several *built-in* service, that will defined as `lsvr_*.c`
files, each file can singly build as a DLL/so file, or build together with
lsvr_init.c file. 

In loki, you must create a `lk_State` to contain all information loki used,
loki doesn't use global variables. A `lk_State` is also a `lk_Service`, and a
`lk_Service` is also a `lk_Slot`. To get the name of a slot, just cast it to
`const char*`.

A service has a handler to register slots, all slots it's registered are
prefixed the name of the service. Service's name limited to 31 characters, and
the name of slot are limited to 63 character. e.g. If you have a service 'foo'
and it create a slot 'bar', then the slot is named 'foo.bar'.

You can find a slot by it's name, and send a message to that. That's made by
use API `lk_emit`. After that slot process this message, it may return a
response message to you, defaultly this response will directly send to your
service. (remember your service is also a slot?)

Loki is a simple library that offer these message passing service. It can used
on Windows or POSIX systems. It can load DLL/so to get new services. If you
have a `foo.dll` on Windows, you should only define a entry function named
`loki_service_foo`, then Loki can load it and offer new service.

Loki is a multi-thread library, but every single service's handler are running
in sequence just like single thread programs. You needn't use lock in a single
service, and use message to communicate with other service.

Loki may offer such built-in service:
  - timer: register timer to callback after several times.
  - task:  to run a long-time task in other thread, or run a poll thread
           backward.
  - socket: offer network ability. Implemented my other library
            [znet](https://github.com/starwing/znet).
  - harbor: multi-process loki server support.
  - logger: logger whatever you want.
  - monitor: to get internal informations about loki services.


PLAN
----

Loki's core library is completed, the built-in services are work-in-progress.


License
-------

Loki use MIT license.

