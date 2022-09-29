
# Build

```bash
cmake -S . -B build -G="MinGW Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build
# To clean
rm build
```

- `mingw-gcc` with `mingw32-make` may not work. (Use `llvm-clang` instead)
- Lib of seal can be compiled by 
  - `msvc-cl`, `mingw-gcc` or `llvm-clang`. 
- Need `c++17`.

# To Do

- [ ] Implementing Hash Function
- [ ] Refactoring Bloom Filter
- [ ] Implementing C/S demo 