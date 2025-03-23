# bloomfilter
* https://zhuanlan.zhihu.com/p/140545941

判断 url 是否访问过
* 数据库, set, 存 hash
* hash + bitmap
* 升级的存储模型: multiple hash + bitmap
  * 一般的 BF 只支持 insert, CBF 进一步支持 delete
  * 最佳实践: Wherever a list or set is used, and space is at a premium, consider using a Bloom filter if the effect of false positives can be mitigated.

model
* map $n$ elements by $k$ hash functions into a bitmap with size $m$
* 无 false negative, 有 false postive
![model](https://s2.loli.net/2022/10/04/RIAnLVJb4sZdTfH.png)

## parameters
false positive probability
* 不在 BF 中的元素被判断为在 BF 中的概率
* 近似为随机一个元素在 BF 中的概率
  * 也就是 k 个 hash 对应的位全部被设置过的概率: $f' = (1 - p')^k$
  * 任意一个位没被设置过的概率: $p' = (1 - \frac{1}{m})^{nk} \approx (1 - e^{-\frac{nk}{m}})$
  * 近似为 0 bits 在 bitmap 中的占比: $\rho \approx p' ?$
    * $E(ρ) = p'$

合理的 hash 函数数目
* 最小化 false positive 关于 k 的函数
* 经求导, 结论: $k = ln 2 · (m/n)$
* false positive rate f is (1/2)k ≈ (0.6185)m/n

bitmap 大小的下界
* Given $n$, $\epsilon$, **minimize** $m$
  $$
  2^{m}\left(\begin{array}{c}
  {{m+\epsilon(u-n)}}\\ {{m}}\end{array}
  \right)
  \ge \left(\begin{array}{c}{{u}}\\ {{n}}\end{array}\right)
  $$
* when $n$ is small compared to $\epsilon u$
* Deduced: lower bound $n\ log(1/\epsilon)$

Let $f \le \epsilon$, from result from last section, we have a factor $ln2$ ??

* It's a approx... ? or because optimal ?
* 个人理解, for optimal BF, the lower bound is large

hasing set 和 BF 的区别
* hashing set 是只有一个 hash 函数的平凡 BF
* hashing set: hashing each ele into logn bits leading 1/n fpp
* BF: constant bits per ele with constant fpp

## operation
* union of set
  * the same number of bits
  * the same hash function
* **halve**
  * Suppose that the size of the filter is a power of 2
  * **OR** the first and second halves together
  * When hashing to do a lookup, **the highest order bit** can be **masked**
* **intersection** of set
  * approximate
  * when both set a bit:
  * $a = b \in S1 ∩ S2$
  * $a \in S1 − (S1 ∩ S2),\ b \in  S2 −(S1 ∩S2)$

## variant
* each has a range of m/k consecutive bit locations disjoint from all the others
* parallelization of array accesses
* "Disjoint Hash Area" Version ?
* counting bloom filters
* compressed bloom filters
