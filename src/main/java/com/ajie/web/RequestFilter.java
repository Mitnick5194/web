package com.ajie.web;

import java.io.IOException;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ajie.dao.pojo.TbUser;

/**
 * 对请求进行拦截处理
 * 
 * @author niezhenjie
 */
public class RequestFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(RequestFilter.class);

	/** 忽略验证的uri */
	protected List<String> ignoreUri;

	/** 编码 */
	protected String encoding;

	/** 远程用户服务 */
	protected RemoteUserService userService;

	/** 登录链接 */
	protected String loginUrl;

	public RemoteUserService getUserService() {
		return userService;
	}

	public void setUserService(RemoteUserService userService) {
		this.userService = userService;
	}

	public static Logger getLogger() {
		return logger;
	}

	public List<String> getIgnoreUri() {
		return ignoreUri;
	}
	

	public String getLoginUrl() {
		return loginUrl;
	}

	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	public void setIgnoreUri(List<String> ignoreUri) {
		this.ignoreUri = ignoreUri;
	}

	public String getEncoding() {
		return encoding;
	}

	public void setEncoding(String encoding) {
		this.encoding = encoding;
	}

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {

	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		request.setCharacterEncoding(encoding);
		String uri = req.getRequestURI();
		if (ignoreUri.contains(uri)) {
			chain.doFilter(request, response);
			return;
		}
		TbUser user = userService.getUser(req);
		if (null == user) {
			userService.gotoLogin(req, res);
			return;
		}
		// 验证是否有权限
		boolean hasRigth = userService.checkRoleForUrl(user, req.getRequestURI());
		if (!hasRigth) {
			logger.debug(user.toString() + " 无访问权限: " + uri);
			res.sendError(HttpServletResponse.SC_FORBIDDEN);
			return;
		}
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {

	}

}
