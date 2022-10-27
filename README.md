## Introduction
面向位置保护的隐私距离计算与近邻检测

## Build

**Requirement**
- c++17+
- seal-4.0

### Linux / wsl
```bash
mkdir build
cd build 
cmake ..
make
```

Specify compiler and build toolchains
```
CC=clang CXX=clang++ cmake .. -G=...
```

### Windows
Surport only non-interactive version(socket using posix).

```bash
cmake -S . -B build -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build
# To clean, always do
rm build
```

- `mingw-gcc` with `mingw32-make` may not work. (Use `llvm-clang` instead)
  - Maybe problem of `gcc` 
- Lib of seal can be compiled by `msvc-cl`, `mingw-gcc` or `llvm-clang`. 

## Guide
### Executable
- `./demo` -- Local version to test the protocol
- `./server && ./client`
  - C/S version
- `./ts && ./tc`
  - Generate Benchmark in `*.csv` format.

### Get help
Example
```bash
./server --help
```
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
To use in pplp:
```
./build/server $(python3 ./src/get_pos.py)
```

## To Do
- [x] Add serialization for Bloom Filter
- [x] Implementing C/S demo 
- [ ] ~~Hash function (on blind distance)~~
- [ ] ~~Set parms of RNG (size of random number)~~
- [ ] ~~Secure parms~~
