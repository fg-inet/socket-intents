The Socket Intents Framework
=====================================

__Socket Intents__ augment the socket interface to enable the application to express what it knows about its communication patterns and preferences. This information can then be used by our proactive policies to choose the appropriate interface, tune the network parameters, or even combine multiple interfaces.  
This framework implements a prototype of Socket Intents and enables applications to use them.
Note that Socket Intents *do not provide any guarantee* of any specific kind of service. They are strictly best-effort.

The actual decision-making is implemented within the __Multi Access Mananger__, a daemon that manages the various network interfaces on a host. The __policy__ is loaded as a shared library within the Multi Access Manager.

Copyright
-----
Copyright (c) 2013-2015, Internet Network Architectures Group, Berlin Institute of Technology,
Philipp Schmidt and Theresa Enghardt and Mirko Palmer.  
All rights reserved.  
This project has been licensed under the New BSD License.


Building and Installing the Socket Intents Framework
-------------------------------------------------

__Supported platforms:__ Linux (we use mainly Debian and Ubuntu), OS X

__Prerequisites:__ cmake, pkg-config, bison, flex, libltdl-dev, libevent-dev, libglib2.0-dev, libargtable2-dev, uuid-dev, libnl-3-dev libnl-3-genl-dev, libnl-idiag-3-dev, libnl-route-3-dev, (liburiparser-dev)

To build and install:

```sh
$ mkdir build
$ cd build/
$ cmake ..
$ make
$ sudo make install
```

This will install:
* The client library *libmuacc-client.so*, containing the Socket Intents
* The Multi Access Manager binary *mamma*
* The policies for the Multi Access Manager as dynamically loaded libraries, to a subdirectory called *mam-policies*
* The Socks Daemon binary *muacsocksd*
* The header files to let you use the client library and/or write your own policies

After installing and before running the Multi Access Manager, you may have to update the shared library cache using
```sh
ldconfig
```

Testing the Socket Intents Framework
------------------------------------

First, you need to run the __Multi Access Manager (MAM)__ with a policy.

1. Pick a policy from the policies subdirectory of the source tree, e.g., policy_sample, and create or adjust its configuration file, e.g. *policy_sample.conf*:
  * Adjust the "prefix" statements to contain the current IP prefixes of the interfaces you want the MAM to manage. Make sure they are "enabled". You have to set separate prefixes for IPv4 and IPv6 addresses.
  * Example:
```
policy "policy_sample.so" {
};
prefix 192.168.0.0/24 {
	enabled 1;
}
```
  * Depending on the policy, you may want to add additional parameters or options to the prefix statements, e.g. for *policy_sample.conf* to make one of them the default interface:
```
policy "policy_sample.so" {
};
prefix 192.168.0.0/24 {
	enabled 1;
	set default = 1;
}
```
2. Run the MAM executable *mamma* (MAM Master) with your policy configuration file:
```
$ mamma policy_sample.conf
```
  If it works correctly, you should see output from the policy, e.g.:
```
Policy module "sample" is loading.
Configured addresses:
    AF_INET: 
        192.168.0.23 (default)
    AF_INET6: 
        (none)
Policy module "sample" has been loaded.
```
  If the list of local addresses does not show up, check mamma's output for error messages, such as: loading of module failed: file not found. If this happens, check the configuration file again and make sure the policy .so file has been correctly built and installed to the policy path, e.g. /usr/local/lib/mam-policies.

Now, you can build and run an initial test, e.g. with *make check*

To test with different parameters, run the following to see what is available:
```sh
./tests/socketconnecttest --help
```

Adding a new application
------------------------

We recommend to use the *Socketconnect API*.

__How it works:__

* Before sending or receiving something to a particular host and port, the application calls socketconnect to get a socket which is connected to that destination. When called the first time, this will be a newly connected socket (return value is 1).
* The socket that was returned is also stored in a socket set, a collection of sockets that have the same destination and type, and can thus be used interchangeably by the application. However, they may have different source addresses or socket options.
* Once the application has finished sending or receiving, it can mark the socket as free for reuse by calling socketrelease.
* The next time socketconnect is called, it is possible that an already existing socket from the socket set is returned (return value is 0).
* When the socket is no longer needed, instead of releasing it, it can be closed by calling socketclose.

You can find the relevant functions in clib/muacc_client.h, or, if you invoked make install, in $LOCAL_INCLUDE_PATH/libmuacc-client/muacc_client.h

__The alternative:__
In addition to socketconnect, there is also the low-level Socket API, where the socket library calls are extended with a socket context parameter.

Troubleshooting
---------------

* Enable debug output: In each source code file, there are #defines such as CLIB_IF_NOISY_DEBUG0. Set them to "1" and compile/install again to get more debug output from the library.
* Debug levels: <component>_NOISY_DEBUG0 is usually for displaying which functions are called, <component>_NOISY_DEBUG1 is errors/warnings, <component>_NOISY_DEBUG2 is very verbose step by step debugging
* Add your own debug output: For an "improved printf" that includes function name and line number, add DLOG lines such as DLOG(CLIB_IF_NOISY_DEBUG0, "Sample debug statement.\n"); to the code and compile/install again.


Further documentation
---------------------

You can generate API documentation using Doxygen. From the top directory of the repository:
```sh
$ doxygen Doxyfile
```
