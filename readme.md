<!--每个请求都会经过过滤器，如果需要对所有请求做处理，可以在过滤器中处理
为区别服务器是本地还是线上，在过滤器向request域中添加一个标识（这里是使用配置一个叫服务器id的标识），前端通过jstl读出该标识，然后在nginx前端代理区别每个请求是服务器还是线上的，可以解决静态资源(不能用于外部静态资源里面静态资源，如css里面的图片)的正向代理映射问题，用法例子：
<script src="biz/${serviceId}/commom/common.js"></script>(当serviceId为空时，src="biz//common/common.js",多一个/不影响)
biz是项目名：如blog、sso
本地规定服务器id是0xff即255
注：serviceId配置里配十进制，使用时需要转成以x开头的16进制 -->
上述已过时
使用下面的：
由于使用nginx反向代理后程序获取到的url是代理后的（如浏览器访问www.nzjie.cn/loadblogs，经过代理访问链接编程127.0.0.1:8080/blog/loadblogs，如果程序直接过去url和uri，得到的结果是代理后的），在处理一些重定向或转发就会导致路径不一致，可以在nginx将原信息放到header里面解决这个问题
proxy_set_header uri  $request_uri;
小程序请求规则：
因小程序不能携带cookie，但能自定义头部，所以可能通过响应头保存session信息
小程序请求规范：在header中加入标识这是小程序的请求：HDMK(header mark):MINIPGRAM(MiniProgram)

aj请求返回状态码：
200	成功
300	 成功状态码 , 调用结果为空
400	无session信息
403	无权限
500 有错误或异常抛出
