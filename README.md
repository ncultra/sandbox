# sandbox
QEMU Live Patching (sandbox)
============================

The sandbox live patching module is designed to be linked into other programs, and the first implementation is for QEMU. There are two requirements for an application to support the sandbox:

Requirements
------------
QEMU, or any application that requires live-patching, must meet at least the following requirements:
* create a root-only local domain socket for communication with the raxlpxs utility program.
* create an independent thread to service the socket

The sandbox component will listen on the domain socket for any live-patching messages. Aside from the sandbox thread, QEMU executes normally.

Components
------------
1. libsandbox.o and sandox-listen.o. These object files should be linked into the application.
2. raxlpxs. this is a version of the utility used for xen live patching. It is intended to be merged into the xen version.
3. extract-patch. The single implementation supports QEMU using a command-line option (--qemu).

Runtime
-------
Each instance of QEMU has a unique domain socket, named "sandbox-sock\<pid\>" where pid is the process id of the application. The socket is created in the same directory that the application resides in.

Nothing happens with the sandbox until the raxlpxs utility connects to the socket, which could be months or years after the application was started.

Messages are exchanged via the domain socket. The sandbox supports the following messages:

1. info
2. list applied patches
3. apply patch
4. remove patch
5. test


Notes
------------

###sandbox size###
The "sandbox" is actually an area in the .text segment that is full of no-ops. The default size of the sandbox is 4k. Live patches are copied to this area. The "sandbox" is not dynamically allocated, so its important to make the sandbox large enough to hold the anticipated number of patches.

###logging###
By default every message over the domain socket is logged to a local text file. This can be turned off. 


###Debugging messages###
In the current build debugging messagez are turned on and are quite verbose. These should be turned off before deployment. The can be re-enabled if necessary.

