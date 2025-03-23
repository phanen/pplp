SoK: Oblivious Pseudorandom Functions

OPRF
* MPC 视角的 OPRF
* strong / weak OPRF
* 使用 OPRF  构造 OT
![image-20221101173124396](https://s2.loli.net/2022/11/01/p1fkTDy7JjIcUOV.png)
* 也可以构造 ROT, OT Extension

## Naor-Reingold PRF
* Freeman OPRF
  * 基于Naor-Reingold PRF
  * 第一个

OT 版本
![image-20221101191630010](https://s2.loli.net/2022/11/01/BtExs4IPCQODuvl.png)

同态版本
![image-20221101194229180](https://s2.loli.net/2022/11/01/3xVYA9B7TsEDZ8U.png)

## Hashed Diffie-Hellman
![image-20221101202449645](https://s2.loli.net/2022/11/01/YvjecUigBa69pPF.png)

## Dodis-Yampolskiy PRF
![image-20221101202533363](https://s2.loli.net/2022/11/01/jbmlHrEDvheM5dC.png)

## Generic Techniques
MPC 构造

evaluate any PRF, obliviously w.r.t. secret input x of the client and secret key k of the server.
![image-20221101202635643](https://s2.loli.net/2022/11/01/VIE1AHgaXwlTNO5.png)

ROT 构造
![image-20221101202704188](https://s2.loli.net/2022/11/01/729Sku4nRpNywm3.png)

Unique blind signature 构造
![image-20221101202933856](https://s2.loli.net/2022/11/01/maLtfAPNUn3ciX9.png)

## security
Unlinkability
* Inability of Server
* 不知道 token 是哪一次签的
  * 也就是不能把盲 token 和 token 匹配...
    * 这是盲签名的性质吧...
* 但这有什么意义...
* 实际上描述的好像更强:
  * 不能将盲化值和随机分布区分
  * sign 的 view 和 redempt 的 view 相互独立
* 基于: Blind 和 随机 sample

one-more-token
* Inability of Client
* 给定一堆带签名 token, 不能伪造一个新的 token 的签名
* Imply: 不能通过一堆签名, 来榨取利用私钥的信息
  * 私钥的唯一作用就是签名
  * 就算没弄到私钥, 累积信息太多, 也可能伪造出来
  * 如果伪造出来了, 可以说利用了隐含的私钥信息
  * 而这个性质强调隐含的这点信息是无法利用的
* 基于: ElGamal 的 one-more-decryption security

key-consistency
* Ability of Server
* 这一点是协议自身存在的漏洞
* 如果 Server 对不同用户用不同 sk, 那么可以单纯利用 sk 对接入的用户做区分, 具体如下
  * Sign 阶段: 当用户发送来盲化 token 的时候, 记录下来
    * (也就记录了 sk 和 盲化 token 的匹配)
  * Redempt 阶段: 用户发来 token 的时候, 必须知道对应的 sk
    * 知道 sk 了, 为啥不知道 token
    * 也就能够知道 token 和对应的盲 token
* 防范: commit to sk... 共识
* 注意, 同用户的一批 token 所用 sk 的一致性已经用 NIZK 保证了

