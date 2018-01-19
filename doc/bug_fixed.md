## 项目
### 登陆操作
 * bug：密码是以明文的方式进行传递的
 * fixed：修复方式： password= sha256（验证码 + sha256(用户名+密码)）
 * good-way： 每次哈希值都是变换的
 
 ### 敏感数据传输怎么办？
 * 增加证书，走https通道
    证书需要向CA申请，购买，或者免费的证书
 * 非堆成算法进行加解密运算
    目前参考知乎给的意见，我编写了RSA1024的加解密（后台JAVA）
    前段采取开源框架（https://github.com/travist/jsencrypt）
    测试页面见：encryption.html
    
 