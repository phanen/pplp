* sgx <https://zhuanlan.zhihu.com/p/457710785>

## A Minimalist Approach to Remote Attestation

remote attestation
* 确保设备是否合法地执行, 侦测识别用户对软件的非授权篡改
* 作为 Trusted Computing 要求
* 技术分类
    * software-based attestation
    * static root of trust
    * dynamic root of trust


ra protocol
![img:ra-protocol](https://i.imgur.com/jq7v2uv.png)
* Chal 验证 Prov (device) 的 internl status 是对的
* k 保证了 attest 的访问权, 但如何防止 Prov 作假?
* attest 类似 mac: 确保数据完整性和认证, 并对内存的一段区域做 commit?
* 和 MAC 的区别? 中断


## VRASED: A Verified Hardware/Software Co-Design for Remote Attestation
* IoT device care less about security/safety
* prevent -> high cost
* detect -> we have ra
* missing aspect of RA -> formal verification
* verifiable-by-design
* MSP430


## SCRAPS: Scalable Collective Remote Attestation for Pub-Sub IoT Networks with Untrusted Proxy Verifier


* RA: trusted Verifier, untrusted Prover
* CRA: scalabillity/efficiency
    * one-to-many
    * many-to-many


设计挑战
* Prover actively interacts with ProxyVerifier and queries it for any pending updates.
    * 迷惑, 这不就是 sync
* pk via smartcontract?
    * 那之前是怎么用 symmetric key 的
    * 或者说 m2m 用 pk + sc 更合适?
* blockchain 没法生成 nonce

