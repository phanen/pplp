# proximity test

## 2017 The Long Road to Computational Location Privacy: A Survey
https://ieeexplore.ieee.org/abstract/document/8482357

goal
* protect location privacy of users
* while still allowing them to enjoy geolocated services

technique
* data perturbation
* data encryption
* fake data generation

use cases
* real-time offline batch

outline
* 实际威胁 评估指标 架构
  * TTP, NTTP, P2P, local
* 保护机制
  * Mix-zone
  * generalization-based (k-anonymity)
  * dummies-based
  * perturbation-based
  * protocol-based

其他的分类办法
* obfuscation mechanisms and anonymization mechanisms
* cryptographic mechanisms and shared information reduction mechanisms

protocol-based
* Louis, Lester and Pierre
* PrivStats
* MobiCrowd
* C-Hide&Seek 格点
* equality testing (Narayanan)
* SRide

另一篇综述
https://ietresearch.onlinelibrary.wiley.com/doi/10.1049/iet-ifs.2019.0125

## 2007 Louis, Lester and Pierre: Three Protocols for Location Privacy

pierre
* 粒度, 划分网格, 将不同的格点归约到一点, 本机只提供所属格点的中心
* 密文相乘, 相等检测后只需要发送乘积

review
* user [16, 114].
* Furthermore, local WiFi network signal strength [6] or availability [133], accelerometers [7], and even ambient sound and light [9] have also been shown to leak location information.

## 2008 Private Queries in Location Based Services: Anonymizers are not Necessary

特点
* 使用 PIR, 并展示可行性
* 不需要 TTP
* 抵抗  correlation attacks
* nearest-neighbor search


## 2009 A Location Privacy Aware Friend Locator

FriendLocator
* 需要 NTTP
* encrypted + grid-based mapping of locations
* 用户把自己的位置归约到格点, 然后发送加密位置给服务器, 服务器判断格点是否接近
* 自适应调整格点的粒度
  * Baseline (另一种静态的方法)

review
* spatial cloaking (该方案只不过是 adapt 的形式)
* range/kNN queries (public data, 压根就不是一个场景)
* distance preserving mapping
* filter-and-refine paradigm

(e1.l = e2.l)
∧((e1.α− = e2.α−) ∨(e1.α− = e2.α+) ∨(e1.α+ = e2.α−))
∧((e1.β− = e2.β−) ∨(e1.β− = e2.β+) ∨(e1.β+ = e2.β−))


review
* 2009 Privacy-Aware Proximity Based Services
* spatial granularity??


## 2010 Private and Flexible Proximity Detection in Mobile Social Networks

场景
![scenarios](https://s2.loli.net/2023/02/26/zRfs7yMNnx4Sg6v.png)
* 不同人可能需要不同阈值
* 距离的定义, road 场景下 euclidean 未必合理
* 多朋友

vicinity region
* Two users are said to be in proximity of each other
* if the vicinity region of one user contains the location of the other user

Spatial cloaking
* 模糊坐标, 归约到区域之间的比较
* 至多泄漏到区域的信息

transformation approaches
* 坐标变换?? 让服务器不知道客户的具体位置, 但还得进行评估

review
* Mascetti et al. Longitude [4], spatial cloaking + modular transformation prior to sending their locations to the server
* Hide&Crypt, filter-and-refine paradigm
  * 首先, 用户在空间上隐藏其位置并将其发送到服务器
  * 然后, 服务器计算这些掩蔽区域之间的最小和最大距离
  * 根据指定的阈值和计算出的距离, 服务器会对 在/不在/可能在 附近的朋友进行分类 最后一种情况需要改进
  * 改进: a spatial subdivision


## 2011 Location Privacy via Private Proximity Testing

Motivation
* 模糊确认位置: 决策是否和朋友聚会, 是否有人接机
* 基于位置的, 会议签到 (你都到场了还担心隐私)
* 军事... 单位检测 高度机密的作战部队如何提供信息

模型
* 应用于社交网络
* 借助中心实现 p2p 带宽太大, 只考虑 adjacent node
* 假设 用户之间预先共享密钥

contrib
* 比较清晰的 问题建模
* proximity testing 归约到 equality testing (PET)
  * 位置归约到六边形格点, 然后比较所在格点
* location tags: 时空关联的 secret, 用来增强 PET 协议?


前两个协议
* 同步的 PET, 基于离散对数
  * 欺骗问题: 半诚实安全, 但是恶意的参与方可以给出 近 的回复
* 引入 oblivious server  的 PET, 用户之间是异步的, 解决了欺骗的问题


location tags
* Reproducibility 同时空下, 产生的标签是 模糊唯一, 可以 match
* Unpredictability 敌手不在同一个时空就构造不出来 (时空固有信息熵

得到大小的 PSI
* 使用同态加密可以构造, 结果是一方获知两方交集大小
* 首先 A 构造一个 多项式, 使得 A 的所有元素在上面都是 0, 发送加密的多项式
* B 计算自己的元素在 多项式上的值, 盲化后发回去
* A 计数零值

relaxed PSI...


## 2012 SHARP: Private Proximity Test and Secure Handshake with Cheat-Proof Location Tags

特点
* secure handshake
* one-to-many proximity test
* share no prior-secrets
* grid-based, 自适应

过程
* A -> S -> nearSet
* A 发送给 S: 希望发给哪个 user group
* S 广播 给 A 和 user group
* 各个 user 构造自己的 location tags
* A 对每个 f 计算 B_f

在 key establishment 阶段, 不用交互, 就能排除 far 的用户

fuzzy extractor


## 2015 InnerCircle: A Parallelizable Decentralized Privacy-Preserving Location Proximity Protocol

def
* mutual 位置近邻 和 one-way 位置近邻
  * collision prevention
  * discovering friends in the vicinity
* decentralized privacy-preserving location proximity

Single- vs. Multi-run security
Discretization degree

contribution
* only one round trip using a parallelizable algorithm
* 方案: B 完成所有的同态计算, 计算出一个混淆表, 回复给 A
  * bf 方案: (r\*i+s) 存表, 混淆 r\*d+s, 查询目标在不在表中
  * 该方案: (d-i)*r 存表, 查询: 零在不在表中

review
* Pierre protocol [35]
* refer the readers to the surveys by Krumm [19] and Terrovitis [30]


## 2017 Location based handshake and private proximity test with location tags

contribution
* 使用 spatial-temporal tag 的新的位置表示方式
* handshake and private proximity test
  * 避免密钥交换, 不需要预先分享秘密
  * Bloom filter + fuzzy extractor

review
* 早期的工作基本是 用户和一个公开的数据库交互, 比如查询附近的某某设施, 使用 k NN 之类的办法, 设法泛化自己的位置,
* 而近邻检测是一种不同的应用场景, 他是 p2p 的本质上是需要用户之间交互的
* 近邻检测虽然只是 一个 p2p 的问题, 为了保护隐私却往往不得不引入第三方
* 基于网格的办法, 降低计算成本也降低精度, 同时隐私有风险, 有些协议甚至还要引入第三方服务器

## 2019 ridesharing TOPPool
https://eprint.iacr.org/2021/812.pdf

TOPPool
* a decentralized platform
* for time-aware,
* optimized
* privacy-preserving ridesharing

Endpoint-based matching
Intersection-based matching
Optimal matching Threshold ridesharing
* A 与 B 的路线有一段足够重合的区域


Threshold PSI -> PSI
* 只有当交集足够大时, 才能得到 PSI 的结果

Endpoint functionality
time-aware ridesharing

O-PrivatePool
* TPSI to PSI protocol
* achieve a remarkable speed-up in IS

TOPPool
* extends O-PrivatePool
* include the dimension of time in both intersection and
endpoint-based matching


## Funshade: Functional Secret Sharing for Two-Party Secure Thresholded Distance Evaluation

* MPC: communication intensive
* FHE: computational intensive
* FSS? (Functional Secret Sharing)


## 2014 Location Privacy of Distance Bounding Protocols

Distance bounding protocol
* 一种类似的研究: 一个实体(verifier) 确定另一个 实体(prover)离自己 距离的 上界
* ?? 给消息打个时间戳, 然后计算来回的时间来判断距离??
* chaum 有研究过


## 2020 Where are you Bob? Privacy-Preserving Proximity Testing with a Napping Party


## Geosocial Query with User-Controlled Privacy
## 2014 Privacy-preserving distance computation and proximity testing on earth, done right.
