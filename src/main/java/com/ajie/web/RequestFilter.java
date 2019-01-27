package com.ajie.web;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
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

import com.ajie.chilli.common.ResponseResult;
import com.ajie.chilli.utils.common.JsonUtils;
import com.ajie.chilli.utils.common.StringUtils;
import com.ajie.chilli.utils.common.URLUtil;
import com.ajie.dao.pojo.TbUser;
import com.ajie.sso.role.RoleUtils;
import com.ajie.sso.user.UserService;

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

	/** 登录模式 -- 本系统登录 */
	protected static final String LOGIN_MODE_NATIVE = "native";

	/** 登录模式 -- 跳转到sso系统登录 */
	protected static final String LOGIN_MODE_SSO = "sso";

	/** session过期状态吗 */
	protected static final int SESSION_INVALID = 400;

	/** 验证模式 —— 拦截或忽略 */
	protected String mode;

	/** 对此类uri进行拦截/忽略验证 */
	protected List<String> uriList;

	/** 登录模式，本系统自行处理还是跳到sso系统登录 */
	protected String loginMode;

	/** oss系统路径 */
	protected String ossHost;

	/** 编码 */
	protected String encoding;

	/** 远程用户服务接口 */
	protected UserService userService;

	/** 登录链接 */
	protected String loginURL;

	public UserService getUserService() {
		return userService;
	}

	public void setUserService(UserService userService) {
		this.userService = userService;
	}

	public String getMode() {
		return mode;
	}

	public void setMode(String mode) {
		this.mode = mode;
	}

	public String getLoginMode() {
		return loginMode;
	}

	public void setLoginMode(String loginMode) {
		this.loginMode = loginMode;
	}

	public void setOssHost(String ossHost) {
		this.ossHost = ossHost;
	}

	public String getOssHost() {
		return ossHost;
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
		// 配置不拦截路径检验模式
		if (StringUtils.eq(FILTER_MODE_IGNORE, mode)) {
			// 不拦截的路径，直接过
			if (URLUtil.match(uriList, uri)) {
				chain.doFilter(request, response);
				return;
			}
		}
		// 拦截路径校验模式
		if ((StringUtils.eq(FILTER_MODE_INTERCEPT, mode))) {
			if (!URLUtil.match(uriList, uri)) {
				chain.doFilter(request, response);
				return;
			}
		}

		TbUser user = userService.getUser(req);
		if (null == user) {// 本地缓存没有找到 sso系统也没有找到
			if (LOGIN_MODE_NATIVE.equals(loginMode)) {
				// 只适用于ajax请求
				ResponseResult ret = ResponseResult.newResult(ResponseResult.CODE_SESSION_INVALID,
						"session is invalid");
				PrintWriter writer = response.getWriter();
				writer.write(JsonUtils.toJSONString(ret));
				writer.flush();
				writer.close();
				return;
			}
			gotoLogin(req, res);
			return;
		}
		//
		boolean right = RoleUtils.checkRole(user, uri);
		if (!right) {
			logger.debug(user.toString() + " 无访问权限: " + uri);
			res.sendError(HttpServletResponse.SC_FORBIDDEN);
			return;
		}
		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {

	}

	/**
	 * 跳到sso系统进行登录
	 * 
	 * @param req
	 * @param res
	 */
	private void gotoLogin(HttpServletRequest req, HttpServletResponse res) {
		StringBuffer refsb = req.getRequestURL();
		String query = req.getQueryString();
		String ref = "";
		if (null != refsb) {
			ref = refsb.toString();
		}
		if (!StringUtils.isEmpty(query)) {
			try {
				ref += "%3f" + URLEncoder.encode(query, "utf-8");
			} catch (UnsupportedEncodingException e) {
				logger.warn("不支持utf-8字符编码转换" + query);
			}
		}
		if (!ossHost.endsWith("/")) {
			ossHost += "/";
		}
		try {
			res.sendRedirect(getOssHost() + "gotologin.do?ref=" + ref);
		} catch (IOException e) {
			logger.error("跳转到oss登录页面失败");
		}
	}

	public static void main(String[] args) {
	}

}
