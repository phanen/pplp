PPLP: Privacy-Preserving Location Proximity (面向位置保护的隐私距离计算与近邻检测)

## Build

* [seal-4.1](https://github.com/microsoft/SEAL.git)
```bash
git clone https://github.com/microsoft/SEAL.git
cd SEAL || exit
CC=clang CXX=clang++ cmake -S . -B build
CC=clang CXX=clang++ cmake --build build
sudo cmake --install build
```

* toolchains: cmake, g++/clang++, python3
* termux(for android)

### Linux/WSL
```bash
mkdir build && cd build || exit
CC=clang CXX=clang++ cmake -S . -B build
CC=clang CXX=clang++ cmake --build build
```

### Windows
Non-interactive version only (Generate Makefile using `llvm-clang` and `mingw32-make`):
```bash
make pplp # after cmake
```
> to choose toolchains in cmake
```bash
CC=clang CXX=clang++ cmake .. -G=...
```

## Usage
After build you will find the follow executable program in your directory:
* `./demo` -- Local version to test the protocol
* `./server && ./client` -- C/S version
* `./ts && ./tc` -- Generate Benchmark in `*.csv` format.

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

## GPS support
`get_pos.py` can print pos, integrate it in pplp by:
```bash
./build/server $(python3 ./src/get_pos.py)
```

## Reverse tunneling
* Port mapping. (anyway, a host with public ip is necessary)
* e.g. Use [frp](https://github.com/fatedier/frp). You may need add the following field.
  ```ini
  [common]
  tls_enable=true
  ```

## Android build
> The following guide help build a vm in termux. Not sure if pplp can be directly built on termux

[Modify `sources.list`](https://mirrors.tuna.tsinghua.edu.cn/help/termux/)
```bash
sed -i 's@^\(deb.*stable main\)$@#\1\ndeb https://mirrors.tuna.tsinghua.edu.cn/termux/apt/termux-main stable main@' "$PREFIX"/etc/apt/sources.list
apt update && apt upgrade
```
ssh on termux
```bash
pkg install openssh -y
/etc/ssh/sshd_config
cat "Port 8022" >>/etc/ssh/sshd_config # banned 1~1024 (no root...)
sshd                                   # For access to GPS of android (no root...)
```
install ubuntu on termux (22.04 currently)
```bash
pkg install proot proot-distro -y
proot-distro install ubuntu
proot-distro login ubuntu
apt install python3 openssh-server -y
# nano /etc/ssh/sshd_config
cat "Port 9022" >>/etc/ssh/sshd_config
cat "PermitRootLogin yes" >>/etc/ssh/sshd_config
/usr/sbin/sshd
```
[build pplp](#build-on-linuxwsl-debian-ubuntu), then run
```bash
./client -h of server of server <ip >-p <port >$(ssh user127.0.0.1 -p 8022 "termux-location" | python3 get_pos_mobile.py)
```

> When open `sshd`, you might need to `mkdir -p <something>`.

## Todo
* [x] Add serialization for Bloom Filter
* [x] Implementing C/S demo
* [ ] ~~Hash function (on blind distance)~~
* [ ] ~~Set parms of RNG (size of random number)~~
* [ ] ~~Secure parms~~
