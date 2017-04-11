# smart_login
本项目用于研究和分享各大网站的各种登陆方式,主要使用selenium+phantomjs或者直接登录的方式


## 关于

由于工作需要，研究了一段时间的新浪微博登陆方式，在网上也查看了很多别人的经验，但是有相当一部分都是转载而且代码老旧，所以打算自己写新浪微博的模拟登陆。这里暂时只有新浪微博的模拟登陆(selenium登录和手机版登陆方式)，以后会慢慢把别的大型网站的模拟登陆代码都补全的，也欢迎各位积极补充


下面是已经实现和待实现的目标

- [x] 微博
- [x] 知乎
- [x] QQ空间
- [x] 京东
- [x] 163邮箱
- [x] CSDN
- [ ] 淘宝
- [ ] 百度
- [ ] 果壳
- [ ] 拉钩

比较典型的是微博这一类的模拟登陆，会用到RSA、Base64等加密算法，关于它的分析过程，我写了[一篇文章](http://www.jianshu.com/p/816594c83c74)，帮助大家理解

## 常见问题

- 关于验证码：本项目所用的方法都没有处理验证码，识别复杂验证码的难度就目前来说，还是比较大的。以我的心得来说，做爬虫最好的方式就是尽量规避验证码。
