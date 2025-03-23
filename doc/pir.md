* <https://en.wikipedia.org/wiki/Private_information_retrieval>
* <https://www.zhihu.com/column/c_1433891764852158464>
* <https://www.zhihu.com/people/wei-liang-yu-he/posts>
* <https://www.secretflow.org.cn/docs/secretflow/latest/zh-Hans/user_guide/psi>

概述
* 形式化定义: 正确性 安全性
* 度量: 上传开销 下载开销 检索速率
* 应用: 疾病库 股票?
* (Chor) 信息论安全 + 单服务器 = 下载所有数据
* 信息论安全 + 多服务器 PIR
* 计算安全 PIR

IT-PIR
* CGKS95: k-server, 每个 server O(n)
* Amb97: k-server, O(n^{1/2k-1})
* CGKS98: k-server, O(n^{1/logk})
* BIKR02: 多项式插值和递归
* Yek08
* Efr09
* DG15

cPIR
* KO97: 二次剩余, 1-server
* CMS99: 隐藏假设, 1-server
* Stern98: 第一次用同态
* DJ.1: Paillier
* MBFK16(XPIR): RLWE, 首个 practical 的 XPIR
* ACLS18(SealPIR): 压缩, 分摊查询

keyword-based (键值对数据库)
* CGN98
* ALP+21: cook hash
* MK22: constant-weight equality operators

如何减少计算
* batch PIR
* preprocessing
* offline/online model


ORAM, OT

## HE-based PIR

查询请求大小(request size), 回答请求大小(response size), 以及服务器计算开销(computation cost). 目前PIR方案基本都从上述三个角度进行改进.
* xPIR: NTT, CRT, Newton quotients
* SealPIR: 压缩查询(expand + 2D), 分摊计算 batch code
    * batch code: 便宜回答一批查询
    * traditional bcode
    * probabilistic bcode


## XPIR : Private Information Retrieval for Everyone

previous PIR
* naive PIR
    * 下载整个数据库
* information-theoretic security PIR
    * 需要 no database replicas collude against users
* sPIR (正交领域)
    * database confidentiality: 用户不能一次获得更多的信息?
* cPIR: single-database computationally-Private Information Retrieval
    * 不需要 database to be replicated, reduce assumption -> no collude
    * 但不实用, 长期一直 slow as naive way... linear cost, over all db, limit db size

contrib
* first usable cPIR
    * 状语.. in many settings, with standard security assumptions, and conservative parameter choices
* 基于 Ring-LWE 的 implementation

简单的 cPIR 范式
![img:basic-cpir](https://i.imgur.com/ZhyK9wW.png)
* 明文乘(absorb) 和密文加: db 方进行, 减少通信量


private keyword search


## Splinter: Practical Private Queries on Public Data

用 FSS 构建 PIR/ 简易 SQL
FSS: only for point and interval functions

过程
* client 从 condition 构建 FSS
* client 发送 query + FSS (去掉 secret 的) 给 each provider
* 如果 query 有 GROUP BY, 那么 provider 就分成 groups
* 对每个 group, provider 运行 evaluation 协议
  * 协议基于 aggregate 函数 + condition 的性质? 待展开讨论
  * 一些协议可能需要更多的通信


## AdVeil: A Private Targeted Advertising Ecosystem

PIR + locality-sensitive hashing
nearest neighbor search

billing metrics
* 允许 ad netwrok 对广告商收费, 对 publisher 付费
* 匿名代理(Tor) + 不可链接匿名 token

targeting 是在带外执行的(如, 每天)
ad delivery 是在用户浏览网页时实时进行的
verify report (用于防止欺诈)要求每个报告少于300微秒



不可链接性
* ad network learns only which ads are viewed (and clicked on) by users
* but not which user saw any given ad

用户自己控制自己的数据
* 可以选择 不 target

fraud prevention
* unlinkable tokens with
metadat
* anonymous flagging of suspicious requests

缺点
* 更高的计算成本
* 只"抑制"广告网络对广告的 track, 不管别的 track
* 需要不同浏览器的合作...


参与方
* users, client
* advertisers(提供广告)
* publishers(网站/app)
* broker(把 ad match 到 users)


ad 和 user 都是 feature vector
搜索 user 的 nn

impression reports 和 click redirects
能防止 bots/攻击者的影响
会秘密地直接停用异常流量(尽可能避免 fraud)

广告的种类
* contextual ad: 基于 content(web/app)
* behavioral ad: 基于 user profile
* real-time bidding

过程
* targeting, delivery, reporting
* targeting
  * 匹配多个 ads to a user
  * Broker 在一个特殊的匿名令牌上提供一个盲签名

PIR is used by the client

one-time-use anonymous tokens
* completeness: valid token 总被 redeem 接受
* unforgeability: prover 不能伪造 valid token 或改变 embedded metadata
* unlinkability: verifier 只知道 the public metadata and token validity
OSPP-without-NIZK?

LSH
vector commitments
anonymizing proxies

setup
* Broker publicly committing to all
the parameters required for targeting, delivery, and reporting
* public bulletin board
* disseminated through a gossip network
