每个请求都会经过过滤器，如果需要对所有请求做处理，可以在过滤器中处理
为区别服务器是本地还是线上，在过滤器向request域中添加一个标识（这里是使用配置一个叫服务器id的标识），前端通过jstl读出该标识，然后在nginx前端代理区别每个请求是服务器还是线上的，可以解决静态资源(不能用于外部静态资源里面静态资源，如css里面的图片)的正向代理映射问题，用法例子：
<script src="biz/${serviceId}/commom/common.js"></script>(当serviceId为空时，src="biz//common/common.js",多一个/不影响)
biz是项目名：如blog、sso
本地规定服务器id是0xff即255
注：serviceId配置里配十进制，使用时需要转成以x开头的16进制