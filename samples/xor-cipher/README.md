# xor-cipher user space module

A simple xor cipher library.

## Building

* '`make`' to build static lib (`libxor_cipher.a`), testing applicaton (`testmgr`) and shared lib (`libxor_cipher.so`). The library links statically to the `testmgr`, so you can launch tests without get anything installed
* `make static` to build static library only
* `make shared` to build shared library only
* `make testmgr` to build testing application (also builds static library)

## Running

To run `testmgr` just build it and type `./testmgr`.