# lwsf

> This project is **NOT** a part of the official monero "core" code, but _may_
> be merged into that project.

> This project is correctly incomplete, so the instructions here are for
> the truly adventurous.

## Table of Contents

  - [Introduction](#introduction)
  - [About this project](#about-this-project)
  - [License](#license)
  - [Compiling Monero-lws from source](#compiling-monero-lws-from-source)
    - [Dependencies](#dependencies)


## Introduction

Monero is a private, secure, untraceable, decentralised digital currency. You are your bank, you control your funds, and nobody can trace your transfers unless you allow them to do so.

**Privacy:** Monero uses a cryptographically sound system to allow you to send and receive funds without your transactions being easily revealed on the blockchain (the ledger of transactions that everyone has). This ensures that your purchases, receipts, and all transfers remain absolutely private by default.

**Security:** Using the power of a distributed peer-to-peer consensus network, every transaction on the network is cryptographically secured. Individual wallets have a 25 word mnemonic seed that is only displayed once, and can be written down to backup the wallet. Wallet files are encrypted with a passphrase to ensure they are useless if stolen.

**Untraceability:** By taking advantage of ring signatures, a special property of a certain type of cryptography, Monero is able to ensure that transactions are not only untraceable, but have an optional measure of ambiguity that ensures that transactions cannot easily be tied back to an individual user or computer.

**Decentralization:** The utility of monero depends on its decentralised peer-to-peer consensus network - anyone should be able to run the monero software, validate the integrity of the blockchain, and participate in all aspects of the monero network using consumer-grade commodity hardware. Decentralization of the monero network is maintained by software development that minimizes the costs of running the monero software and inhibits the proliferation of specialized, non-commodity hardware.


## About this project

The tl;dr is that you if you import this project into your wallet,
you can choose at runtime between a Monero "full" wallet that does
all of the transaction scanning locally, or a Monero "light" wallet
that does all of the scanning remotely. A single C++ `virtual`
interface has two different implementations for Monero wallet
processing.

**The longer version -**

This is a client library for the [Monero light-wallet REST API](https://github.com/monero-project/meta/blob/master/api/lightwallet_rest.md)
(i.e. MyMonero compatible) that implements the [`wallet2_api.h`](https://github.com/monero-project/monero/blob/3b01c490953fe92f3c6628fa31d280a4f0490d28/src/wallet/api/wallet2_api.h)
interface. Downstream projects/wallets can write code that calls into
the `wallet2_api.h` functions to manage a Monero wallet, and select
a "standard" monero wallet by calling
`Monero::WalletManagerFactory::getWalletManager()` or select a
light-wallet by calling `lwsf::WalletManagerFactory::getWalletManager()`.

[`lwcli` illustrates how this works](https://github.com/cifro-codes/lwcli/blob/4a6793608c46f05d959336ea55dd106e0b0339bd/src/main.cpp#L281).
The main function calls a different "factory" function depending on the
CLI arguments. The `lwcli` TUI "draw" code is then given a single
`Monero::WalletManager` interface object that can be one of two
implementations. The `lwsf` manager requires the
user to specify a [LWS](https://github.com/vtnerd/monero-lws) server,
whereas the `Monero` manager requires a monero daemon RPC. The
light-wallet implementation can have quicker sync time, whereas the
monerod implementation will have better privacy guarantees. If you
run your own LWS server, the privacy is identical.

The projects use different file formats for storing data, so
you have to manully import a wallet via seed if you want to
change backends. The files output by the `Monero` factory function
are compatbile with `monero-gui` and `monero-wallet-cli`, as it
uses the same code.


## License

See [LICENSE](LICENSE).


## Compiling lswf from source

### Dependencies

The following table summarizes the tools and libraries required to build.

| Dep          | Min. version  | Vendored | Debian/Ubuntu pkg    | Arch pkg     | Void pkg           | Fedora pkg          | Optional | Purpose         |
| ------------ | ------------- | -------- | -------------------- | ------------ | ------------------ | ------------------- | -------- | --------------- |
| GCC          | 7             | NO       | `build-essential`    | `base-devel` | `base-devel`       | `gcc`               | NO       |                 |
| CMake        | 3.5           | NO       | `cmake`              | `cmake`      | `cmake`            | `cmake`             | NO       |                 |
| Boost        | 1.66          | NO       | `libboost-all-dev`   | `boost`      | `boost-devel`      | `boost-devel`       | NO       | C++ libraries   |
| monero       | master branch | NO       |                      |              |                    |                     | NO       | Monero libraries|
| OpenSSL      | basically any | NO       | `libssl-dev`         | `openssl`    | `libressl-devel`   | `openssl-devel`     | NO       | sha256 sum      |
| libzmq       | 4.2.0         | NO       | `libzmq3-dev`        | `zeromq`     | `zeromq-devel`     | `zeromq-devel`      | NO       | ZeroMQ library  |
| libunbound   | 1.4.16        | NO       | `libunbound-dev`     | `unbound`    | `unbound-devel`    | `unbound-devel`     | NO       | DNS resolver    |
| libsodium    | ?             | NO       | `libsodium-dev`      | `libsodium`  | `libsodium-devel`  | `libsodium-devel`   | NO       | cryptography    |
| Doxygen      | any           | NO       | `doxygen`            | `doxygen`    | `doxygen`          | `doxygen`           | YES      | Documentation   |
| Graphviz     | any           | NO       | `graphviz`           | `graphviz`   | `graphviz`         | `graphviz`          | YES      | Documentation   |

Follow the guide from the [Monero projdect](https://github.com/monero-project/monero/blob/master/README.md#dependencies) for
dependency installation and cloning the Monero repository. Stop
after you've finished the cloning section for Monero, as `lwsf`
will build Monero separately for you.

### Cloning the repository

Clone recursively to pull-in needed submodule(s):

```bash
git clone --recursive https://github.com/vtnerd/lwsf.git
cd monero-lws && git submodule init && git submodule update
```

### Build instructions

Monero uses the CMake build system. Create a folder for the build,
and specify both the Monero source directory and
lwsf source directory:

```bash
mkdir build_lwsf && cd build_lwsf
cmake -DCMAKE_BUILD_TYPE=Release -DMONERO_SOURCE_DIR=/home/user/monero_source /home/user/lwsf_source
cmake --build
```

## Running lwsf

When complete, you should have `lwsf-ledger` executable in
`/home/user/build_lwsf/src` and a `lwsf-api.a` file in the
same folder. Run the `-h` option on `lwsf-ledger` to test
against a LWS server.

### lwsf-api.a

This file is a little tricky to use outright as it doesn't
contain the entire code needed. The remainder of the code
is in `.a` files in the Monero source directory. The best
way to include `lwsf` into another project is to use Cmake
with the [`FetchContent` function](https://github.com/cifro-codes/lwcli/blob/4a6793608c46f05d959336ea55dd106e0b0339bd/CMakeLists.txt#L40).
After running those few lines, you will have a `lwsf-api`
target in Cmake:

```cmake
project(your_project)
include(FetchContent)
FetchContent_Declare(lwsf SOURCE_DIR "${your_project_SOURCE_DIR}/external/lwsf")

if (NOT lwsf_POPULATED)
  FetchContent_MakeAvailable(lwsf)
endif ()

add_library(your_library ...)
target_link_libraries(your_library lwsf-api)
```



