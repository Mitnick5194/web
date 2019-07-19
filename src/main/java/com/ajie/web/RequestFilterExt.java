package com.ajie.web;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ajie.chilli.common.ResponseResult;
import com.ajie.chilli.utils.common.JsonUtils;
import com.ajie.dao.pojo.TbUser;
import com.ajie.sso.role.RoleUtils;
import com.ajie.sso.user.UserService;
import com.ajie.sso.user.exception.UserException;

/**
 * 扩展过滤器，服务小程序的请求（小程序不能带cookie,但能带自定义header）<br>
 * 小程序端将session key保存到header中，在每次请求时带过来即可
 * 
 *
 * @author niezhenjie
 *
 */
public class RequestFilterExt extends RequestFilter {

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		try {
			HttpServletRequest request = (HttpServletRequest) req;
			HttpServletResponse response = (HttpServletResponse) res;
			String mark = request.getHeader(HEADER_MARK);
			if (!HEADER_MINIPROGRAM.equals(mark)) {
				// 普通请求
				super.doFilter(request, response, chain);
				return;
			}
			// 小程序请求
			checkPath(request, response, chain);
			// 需要验证用户是否登录
			// 从header中取出登录信息
			String token = request.getHeader(UserService.COOKIE_KEY);
			TbUser user = null;
			try {
				user = userService.getUserByToken(token);
			} catch (UserException e) {
			}
			if (null == user) {// 没有登录
				ResponseResult ret = ResponseResult.newResult(CODE_SESSION_INVALID,
						"session is invalid");
				send(response, ret);
				return;
			}
			String uri = request.getRequestURI();
			if (checkRight) { // 验证权限
				boolean right = RoleUtils.checkRole(user, uri);
				if (!right) {
					if (logger.isDebugEnabled()) {
						logger.debug(user.toString() + " 无访问权限: " + uri);
					}
					ResponseResult ret = ResponseResult.newResult(CODE_FORBIDDEN, "无权限");
					send(response, ret);
					return;
				}
			}
			chain.doFilter(request, response);
		} catch (Throwable e) {
			logger.error("", e);
			throw e;
		}
	}

	private void send(HttpServletResponse response, ResponseResult ret) throws IOException {
		PrintWriter writer = response.getWriter();
		writer.write(JsonUtils.toJSONString(ret));
		writer.flush();
		writer.close();
	}
}
