`loki` - one-header online game framework
----------------------------------------

`loki` is a online game framework, inspired by cloudwu's
[skynet](https://github.com/cloudwu/skynet).

To start, see the header file
[loki.h](https://github.com/starwing/`loki`/blob/master/`loki`.h).
`loki` now doesn't have documentations for now, but I will finish that after
complete the built-in service.

`loki` is not only used in online game server, but more. It's a *multi-thread*
service *signal/slot* system. Every service register it's own slots, and
send/receive message to offer service. 

`loki` only have one header as it's core. To define `loki` functions (only
allow in only **one** C file), define `LOKI_IMPLEMENTATION` before include
`loki.h`.  `loki` also has several *built-in* service, that will defined as
`lsvr_*.c` files, each file can singly build as a DLL/so file, or build
together with `lsvr_init.c` file. 

In `loki`, you must create a `lk_State` to contain all information `loki`
used, `loki` doesn't use global variables. A `lk_State` is also a
`lk_Service`, and a `lk_Service` is also a `lk_Slot`. To get the name of a
slot, just cast it to `const char*`. You can emit signals to slot by
`lk_emit()`, and process them in a function called `lk_SlotHandler`.

A service must have a function named `lk_ServiceHandler` to register slots.
All slots it registered are prefixed the name of the service. Service's name
limited to 31 characters, and the name of slot are limited to 63 character.

e.g. If you have a service 'foo' and it create a slot 'bar', then the slot is
named 'foo.bar'.

You can find a slot/service by it's name, and send a message to that.After
slot process the message, it may return a response message to you by default.
This response will directly send to your service. (remember your service is
also a slot?)

loki is that simple library offer these message passing service. It can used
on Windows or POSIX systems. It can load DLL/so to get new services. If you
have a `foo.dll` on Windows, you should only define a entry function named
`loki_service_foo`, then loki can load it and offer new service.

loki uses multi-thread, but every single service's handler are running in
order, just like other single thread programs. You needn't use locks in a
single service, you can use message to communicate with other service to avoid
the use of locks.

loki offers such built-in service:
  - timer: register timer to callback after several times.
  - task:  to run a long-time task in other thread, or run a poll thread
           backward.
  - socket: offer network ability. Implemented my other library
            [znet](https://github.com/starwing/znet).
  - harbor: multi-process `loki` server support.
  - logger: logger whatever you want.
  - monitor: to get internal informations about `loki` services.


PLAN
----

Loki's core library is completed.
The built-in services are work-in-progress.


License
-------

Loki use MIT license.

