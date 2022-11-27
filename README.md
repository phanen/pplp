## Introduction
> PPLP: Privacy-Preserving Location Proximity
面向位置保护的隐私距离计算与近邻检测


## Build

### Requirement
- [seal-4.0](https://github.com/microsoft/SEAL.git)
- cmake
- g++/clang++
- python3
- termux(for android)
- windows

Build seal
```bash
sudo apt update && sudo apt upgrade
sudo apt install git cmake clang # clang 可选, 但快
git clone https://github.com/microsoft/SEAL.git
cd SEAL
CC=clang CXX=clang++ cmake -S . -B build
CC=clang CXX=clang++ cmake --build build
sudo cmake --install build
```


### Build on Linux/WSL (Debian, Ubuntu)
```
git clone https://github.com/phanen/pplp.git
mkdir build && cd build
CC=clang CXX=clang++ cmake -S . -B build
CC=clang CXX=clang++ cmake --build build
```

Specify compiler and build toolchains
```
CC=clang CXX=clang++ cmake .. -G=...
```


### Guide
After build you will find the follow executable program in your directory:
- `./demo` -- Local version to test the protocol
- `./server && ./client`
  - C/S version
- `./ts && ./tc`
  - Generate Benchmark in `*.csv` format.

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


### GPS support
`python3 ./src/get_pos.py` will print cmdline flavor coordinate.
To integrate it in pplp:
```
./build/server $(python3 ./src/get_pos.py)
```

### Build on android
> No java or kotlin :joy:

#### build on Ubuntu on termux
> Not sure if pplp can be directly built on termux
[Modify `sources.list`](https://mirrors.tuna.tsinghua.edu.cn/help/termux/)
```bash
sed -i 's@^\(deb.*stable main\)$@#\1\ndeb https://mirrors.tuna.tsinghua.edu.cn/termux/apt/termux-main stable main@' $PREFIX/etc/apt/sources.list
apt update && apt upgrade
```
ssh in termux
```bash
pkg install openssh -y
/etc/ssh/sshd_config
cat "Port 8022" >> /etc/ssh/sshd_config # banned 1~1024 (no root...)
sshd # For access to GPS of android (no root...)
```
ssh on ubuntu (22.04 currently)
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

[build pplp](### Build on Linux/WSL (Debian, Ubuntu))

run
```bash
./client -h <ip of server> -p <port of server> $(ssh user127.0.0.1 -p 8022 "termux-location" | python3 get_pos_mobile.py)
```

> When open service of `sshd`, you might need to `mkdir -p <something>`.

### Build on Windows
Surport only non-interactive version, so you can only
```bash
make pplp # after cmake
```

> If you cannot build... you can try
>   - Generate Makefile using `llvm-clang` and `mingw32-make`
>   - Replace something in Makefile... (I'm forgetful)


## To Do
- [x] Add serialization for Bloom Filter
- [x] Implementing C/S demo 
- [ ] ~~Hash function (on blind distance)~~
- [ ] ~~Set parms of RNG (size of random number)~~
- [ ] ~~Secure parms~~
