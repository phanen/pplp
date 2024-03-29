## Introduction

PPLP: Privacy-Preserving Location Proximity

(面向位置保护的隐私距离计算与近邻检测)

## Requirements
- [seal-4.1](https://github.com/microsoft/SEAL.git)
- toolchains: cmake, g++/clang++, python3
- termux(for android)

## Build

### Linux/WSL 
```bash
git clone https://github.com/phanen/pplp.git
mkdir build && cd build
CC=clang CXX=clang++ cmake -S . -B build
CC=clang CXX=clang++ cmake --build build
```
> tested on debian, ubuntu, arch

### Android

Provide a hack way to run on Android. Check FAQ.


### Windows
Non-interactive version only:
```bash
make pplp # after cmake
```
If you cannot build... you can try
- Generate Makefile using `llvm-clang` and `mingw32-make`
- Replace something in Makefile...


## Usage
After build you will find the follow executable program in your directory:
- `./demo` -- Local version to test the protocol
- `./server && ./client` -- C/S version
- `./ts && ./tc` -- Generate Benchmark in `*.csv` format.

To get manual of specific program, type:
```bash
./server --help
```
the manual
```
usage: ./server [options] ... 
options:
  -h, --host      ip of server (string [=127.0.0.1])
  -p, --port      port of server (unsigned short [=51022])
  -u, --xb        coordinate1 of server (unsigned long [=123456888])
  -v, --yb        coordinate2 of server (unsigned long [=132465777])
  -r, --radius    radius/thershold (unsigned long [=128])
  -?, --help      print this message
```

GPS support
`python3 ./src/get_pos.py` will print cmdline flavor coordinate, integrate it in pplp by:
```bash
./build/server $(python3 ./src/get_pos.py)
```


## To Do
- [x] Add serialization for Bloom Filter
- [x] Implementing C/S demo 
- [ ] ~~Hash function (on blind distance)~~
- [ ] ~~Set parms of RNG (size of random number)~~
- [ ] ~~Secure parms~~


## FAQ

How to build seal
```bash
git clone https://github.com/microsoft/SEAL.git
cd SEAL
CC=clang CXX=clang++ cmake -S . -B build
CC=clang CXX=clang++ cmake --build build
sudo cmake --install build
```

Want to use other toolchains?
```bash
CC=clang CXX=clang++ cmake .. -G=...
```

How to deploy a server in LAN?
- Port mapping. (anyway, a host with public ip is necessary)
- e.g. Use [frp](https://github.com/fatedier/frp). You may need add the following field.
  ```ini
  [common]
  tls_enable=true
  ```


How to build on android?
> The following guide help build a vm in termux. Not sure if pplp can be directly built on termux

[Modify `sources.list`](https://mirrors.tuna.tsinghua.edu.cn/help/termux/)
```bash
sed -i 's@^\(deb.*stable main\)$@#\1\ndeb https://mirrors.tuna.tsinghua.edu.cn/termux/apt/termux-main stable main@' $PREFIX/etc/apt/sources.list
apt update && apt upgrade
```
ssh on termux
```bash
pkg install openssh -y
/etc/ssh/sshd_config
cat "Port 8022" >> /etc/ssh/sshd_config # banned 1~1024 (no root...)
sshd # For access to GPS of android (no root...)
```
install ubuntu on termux (22.04 currently)
```bash
pkg install proot proot-distro -y 
proot-distro install ubuntu
proot-distro login ubuntu
apt install python3 openssh-server -y
# nano /etc/ssh/sshd_config
cat "Port 9022" >> /etc/ssh/sshd_config 
cat "PermitRootLogin yes" >> /etc/ssh/sshd_config 
/usr/sbin/sshd
```
[build pplp](#build-on-linuxwsl-debian-ubuntu), then run
```bash
./client -h <ip of server> -p <port of server> $(ssh user127.0.0.1 -p 8022 "termux-location" | python3 get_pos_mobile.py)
```

> When open `sshd`, you might need to `mkdir -p <something>`.
