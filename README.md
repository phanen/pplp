

## Build

**Requirement**
- `c++17`.
- seal-4.0

### Linux / wsl
```bash
mkdir build
cd build 
cmake ..
make
```


### Windows
Maybe surport non-interactive version only (C/S demo using posix).

```bash
cmake -S . -B build -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build
# To clean, always do
rm build
```

- `mingw-gcc` with `mingw32-make` may not work. (Use `llvm-clang` instead)
  - Maybe problem of `gcc` 
- Lib of seal can be compiled by `msvc-cl`, `mingw-gcc` or `llvm-clang`. 

## To Do
- [x] Add serialization for Bloom Filter
- [x] Implementing C/S demo 
- [ ] Hash function (on blind distance)
- [ ] Cryptographic RNG for blind factor.