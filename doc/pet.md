# privacy-enhance technology
* https://www.zhihu.com/question/37545236/answer/72555948

## K-anonymity
https://www.zhihu.com/question/26710204/answer/33758321

数据的分类
* sensitive data, identifier, quasi-identifier

作用
* 防止 链接攻击
* 每条记录在发布数据前, 都至少与表中K-1条记录无法区分开来. 具有相同准标识符的记录构成一个等价类
* 除非有k-1个人的数据同时被公布, 才可能推断出第k个人是谁

算法
* 保证相同的quasi-identifier下, 至少包含k个不同条目即可
* 所以把原始数据中quasi-identifier逐步隐去, 直到达到这一要求
* 先隐去出生日期, 看看是否满足k-anonymity条件.
* 不行再隐去出生月份, 不行再隐去年份, 性别等.

l-diversity
* 数据缺少 diversity 时候, k 匿名不管用

## PIR
 server S holds a database with n bits, X = (X1 . . . Xn).
 user u wishes to retrieve the value of Xi,
 without disclosing to S the value of i

已有的结果
* 信息论安全: 如果是 a single server, user must receive the entire database(Θ(n))
* 计算安全: the communication cost for a single server is Θ(nε)
  * where ε is an arbitrarily small positive constant.

## KNN
https://zhuanlan.zhihu.com/p/61341071
