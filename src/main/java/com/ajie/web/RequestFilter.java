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

import com.ajie.chilli.utils.common.StringUtil;
import com.ajie.dao.pojo.TbUser;
import com.ajie.web.utils.URLUtil;

/**
 * 对请求进行拦截处理
 * 
 * @author niezhenjie
 */
public class RequestFilter implements Filter {

	private static final Logger logger = LoggerFactory.getLogger(RequestFilter.class);

	/** 忽略模式，对配置的请求忽略拦截 */
	protected static final String FILTER_MODE_IGNORE = "ignore";

	/** 拦截模式，对配置的请求进行拦截 */
	protected static final String FILTER_MODE_INTERCEPT = "intercept";

	/** 验证模式 —— 拦截或忽略 */
	protected String mode;

	/** 对此类uri进行拦截/忽略验证 */
	protected List<String> uriList;

	/** 编码 */
	protected String encoding;

	/** 远程用户服务接口 */
	protected RemoteUserService userService;

	/** 登录链接 */
	protected String loginURL;

	public RemoteUserService getUserService() {
		return userService;
	}

	public void setUserService(RemoteUserService userService) {
		this.userService = userService;
	}

	public String getMode() {
		return mode;
	}

	public void setMode(String mode) {
		this.mode = mode;
	}

	public List<String> getUriList() {
		return uriList;
	}

	public String getLoginURL() {
		return loginURL;
	}

	public void setloginURL(String loginURL) {
		this.loginURL = loginURL;
	}

	public void setUriList(List<String> uriList) {
		this.uriList = uriList;
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
		if (StringUtil.eq(FILTER_MODE_IGNORE, mode)) {
			if (URLUtil.match(uriList, uri)) {
				chain.doFilter(request, response);
				return;
			}
		}
		if ((StringUtil.eq(FILTER_MODE_INTERCEPT, mode))) {
			if (!URLUtil.match(uriList, uri)) {
				chain.doFilter(request, response);
				return;
			}
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

	public static void main(String[] args) {
	}

}
