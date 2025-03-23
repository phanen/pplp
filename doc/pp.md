Privacy Pass: Bypassing Internet Challenges
Anonymously
* <https://github.com/privacypass/challenge-bypass-extension>
* <https://privacypass.github.io/protocol/>

## problems
CDN 增长后, 现状:
* CND 逐渐成为 arbiters
* 往往采用 catch-all 的解决方案来识别和阻止恶意流量
* share IP 后的诚实用户也被限制, 过多的 CAPTCHAS

## contributions

1-RTT protocol (OPRF)
* 轮数
* 改进 CAPTCHAS
* 保证匿名性

当前 client-edge 方案
* 基于 IP 地址的 malicious-reputation scores
* score 高于阈值就会被 challenge
  ![workflow](https://s2.loli.net/2023/02/21/YIn2ku7gAJxDOy9.png)
* 完成 chanllenge 后一段时间可用 cookies 访问 单个 origin, 用 cross-domain cookies 访问多个 origins

## preliminaries

Discrete log equivalence proofs
* 证明两离散对数相等
* 构造并承诺, 新的两个相等的离散对数

Batch DLEQ proofs
* PRNG + seed 得到, 要承诺的 t_i
* 用类似点积的方式计算出两个承诺
* 调用 DLEQ

## intuition

如何设计一个 "token signing + token redemption" 的认证协议

从一个简陋的协议出发
```
T ->
sT <-
```
本质上是服务器给分配了一个秘密 s 用作认证

下面是一系列问题和解决

linkability (S)
* 服务器能够仅根据 T 来区分 sign 的和 redempt 的是否是同一用户
  * (两个不同的 IP) 只要使用同一个 token, 就能断言是同一用户
* 解决: 使用盲化, 服务器不能通过 T 来识别用户 (但仍能用 s 来区分)

malleability (C)
* 同态性的表现, 用户只要获得一个 token, 就可以尝试无限使用
* 由认证方式带来的多花问题
* 解决: 使用 hash

redemption hijacking (A)
* 攻击者在 redemptioin 阶段重放, 直接冒充
* 解决: 使用 MAC 进一步认证

tagging
* 攻击者使用 s 来对用户打标签, 通过标签信息来区分用户
* 解决: 使用承诺, 这里用的是 DLEQ 来承诺所有的用户都用相同的 tag

only one redemption per issuance
* 解决: 一次申请多个 token (但增加了通信负载)
* bandwidth 解决: 一次申请多个, 同时不增加带宽的 batch-DLEQ
