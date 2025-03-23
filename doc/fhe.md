# fhe
Oded Regev
Craig Gentry
Zvika Brakerski

## 2009 Computing Arbitrary Functions of Encrypted Data
https://crypto.stanford.edu/craig/easy-fhe.pdf

how do we formalize what it means to delegate?
* 为避免出现类似: 直接发送电路, 让 alice 自己解密的 naive 情形, 简单形式化地叙述如下
* same amount of computation
  * 解密 eval 的输出结果 和 解密一般的密文 的效率应该是一样的
* compact ciphertexts requirement
  * eval 的输出大小 和 一般密文的大小 应该是一样的
* completely independent
  * 密文的大小 和 eval 函数 f 复杂度 应该无关 (除非 f 是多元输出)
* eval 应该是 effective 的 (计算可行性)
  * 在 TM 花费 T 步计算的函数, 可以用 S 个 gate 的 boolean circuit 表示
  * 其中 S 的上界是 O(k T logT)
  * eval 和 f 是同规模的: O(S g(\lambda))

全同态的局限性
* 有序的密文中, RAM 无法进行二分搜索
  * 有时候(二分搜索) RAM 比 TM 和 电路 更有用 (所以这些模型哪里能够学到呢)
  * (但可以穷搜, 具体如何在密文状态下实现呢
  * 我的想法: 计算每个 i * (target = a[i])
* 解决办法? 如果可以牺牲一部分隐私, 降低成本
* 电路大小必须事先给定?
* 本质: evaluator 在加密状态下不知道 priori


加密机制的安全模型
* one-wayness (最基本的)
* IND-CPA 安全 (CPA 攻击下的语义安全)
  * 无法区分(adv 是 negligible的) c 来自 m0 还是 m1, 即使允许使用加密 oracle
  * 因此加密机制必须是 non-deterministic 的, probabilistic 的
* 可证明安全
  * reduce 到 hard problem 上
* 同态加密机制的安全模型
  * 简单的组合: 安全的普通加密机制 + eval
  * 但 eval 的引入是否让 加密机制更容易破解? (直觉上, 加密算法越 malleable, 越容易破解)


### a simple somewhat HE

对称版本, 一次 1 bit
* keygen: 奇数 p
* 加密 c = m' + pq (m' 是带噪音的 m)
* 解密 m = c' mod p mod 2
* eval
  * 密文上的 add, sub, mul 和明文一致
  * 只要 noise m' 增长不超过 p (否则会被 mod 掉)


非对称版本
* keygen: 公开对 0 的加密作为 pk, (sk = p)
* 加密: 取一些对 0 的加密, 加到 m 上
* 解密: 一致


有多同态?
* 分析噪音的增长规律
* 结论: 总噪音恰好是对噪音消息 m' 的 eval


困难问题假设: Appr GCDs
* 给两个近似是 p 的倍数的数
* 很难计算出他们的公因数是 p



### bootstrap

box1 坏掉后, 就把 box1 装进另一个包含 box1 的 key 的 box2, 在 box2 中完成对 1 的解锁和进一步操作

FHE = somewhat HE + bootstrappable
* 构造一个新的机制 recrypt, 输入加密的 sk1 和 c1, 输出新的加密 c2
* 利用 eval, 计算 decrypt
* 重新对密文进行加密, 更新了噪音, 替换了 sk
* 具体方法: 构造一个 sk 的加密链, 其中 sk_i 用 pk_{i+1} 来加密



### circular security

* 严格意义上, 使用加密链还是不能实现 FHE, keygen 的代价随着 circuit 的深度增长
* keygen 结束后, circuit 的复杂度就决定了, 注定了这个机制就不是 FHE 的
* 那么问题来了: 直接用 pk 加密 sk 是否可行? 会不会破坏安全性质呢



### greasing
bootstrap 的关键在于简化 decryption
* m = c mod p mod 2 = (c - c[c/p]) mod 2 = LSB(c) xor LSB([c/p])
* 但 c * (1/p) 还是太复杂, 以至于无法 bootstrap
* idea: 构建一个新的机制, 在 pk 中嵌入更多的 hint 信息 (一个集合, 它的子集和能够接近 1/p), 增加加密的工作, 减少解密的成本

新的机制
* keygen: pk 多生成一个集合, 有一个子集和是 1/p, sk 多生成一个子集向量
* encrypt:  两阶段加密, c 加密为向量 z (server-aided cryptography 的 trick: 增加加密阶段(server)的工作, 减少解密(user)的成本)
* decrypt: 将加密向量 z 点乘子集向量即可


新机制的安全性
* SSSP(sparse subset sum) + appr GCDs


## 2011 Efficient Fully Homomorphic Encryption from (Standard) LWE

contribution
* 利用 relinearization 技术, 使用 LWE 假设
  * 之前的机制: 基于 ideal rings 的假设
  * 理想格是一种我们所知甚少的特殊类型
* dimension-modulus reduction 技术
  * 缩短 ciphertexts, 降低 decryption 的复杂度, 但不引入新的困难问题假设
  * 之前: artificial squashing, SSSP
* 能用来构造 asymptotically efficient LWE-based single-server PIR
