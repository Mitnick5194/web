package com.ajie.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletInputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.ajie.chilli.utils.common.StringUtils;

/**
 * 防xss注入攻击请求
 *
 * @author niezhenjie
 *
 */
public class XssDefenseRequest implements HttpServletRequest {
	/** 过滤全部标签 */
	public static final int MODE_ALL = 1;
	/** 黑名单方式过滤 */
	public static final int MODE_BLACK = 2;
	/** 白名单方式过滤 */
	public static final int MODE_WHITE = 3;
	/** < ascii码 */
	public final static byte MARK_LEFT = 0x3C;
	/** > ascii码 */
	public final static byte MARK_RIGHT = 0x3E;
	/** '/' ascii码 */
	public final static String MARK_DIVIDE = "/";
	/** 空格ascii码 */
	public final static byte MARK_SPACE = 0x20;
	/** 请求 */
	protected HttpServletRequest request;
	/** 转义列表，如果mode为白名单模式，则是白名单列表，如果是黑名单，则是黑名单列表，标签如script，不用带<> */
	protected List<String> escapeList;
	protected int mode;

	public XssDefenseRequest(HttpServletRequest request) {
		this.request = request;
		mode = MODE_ALL;
	}

	public XssDefenseRequest(HttpServletRequest request, int mode, List<String> list) {
		this.request = request;
		this.mode = mode;
		this.escapeList = list;
	}

	static public HttpServletRequest toXssDefenseRequest(HttpServletRequest request) {
		return new XssDefenseRequest(request);
	}

	static public HttpServletRequest toXssDefenseRequest(HttpServletRequest request, int mode,
			List<String> list) {
		return new XssDefenseRequest(request, mode, list);
	}

	/**
	 * 重写获取参数的方法，过滤特殊标签
	 * 
	 * @param name
	 * @return
	 */
	@Override
	public String getParameter(String name) {
		String origin = request.getParameter(name);
		if (StringUtils.isEmpty(origin)) {
			return origin;
		}
		int mode = this.mode;
		if (mode == MODE_BLACK || mode == MODE_WHITE) {
			origin = escape(origin, escapeList, mode);
		} else {
			origin = escape(origin);
		}
		return origin;
	}

	/**
	 * 凡是<>都转义<br>
	 * <使用&lt; ， >使用&gt;
	 * 
	 * @param origin
	 * @return
	 */
	private static String escape(String origin) {
		origin = origin.replaceAll("<", "&lt;");
		origin = origin.replaceAll(">", "&gt;");
		return origin;
	}

	private static String escape(String origin, List<String> list, int mode) {
		if (StringUtils.isEmpty(origin))
			return null;
		if (null == list || list.isEmpty()) {
			if (mode == MODE_WHITE) {
				origin = escape(origin);
			}
			return origin;
		}
		int len = origin.length(), i = 0, j = 0;
		// 转移后长度一定大于或等于len，指定len吧 省的每次都扩容，1/10是标签，应该没有那么多吧
		StringBuilder sb = new StringBuilder(len + len / 10);
		outer: for (; i < len; i++) {
			char ch = origin.charAt(i);
			if (ch != MARK_LEFT) {
				sb.append(ch);
				continue;
			}
			// 上面遇到了<，寻找有没有>
			boolean find = false;
			for (j = i + 1; j < len; j++) {
				ch = origin.charAt(j);
				if (ch == MARK_LEFT) {
					// 又找到了<，标签里面不可能有<，所以上面的不是标签，从j处再找
					sb.append(origin.substring(i, j));// i是<也要包含进来哟
					i = --j;
					continue outer;
				}
				if (origin.charAt(j) == MARK_RIGHT) {
					// good 找到右标签了
					find = true;
					break;
				}
			}
			if (!find) {
				// 遍历整个都没有右标签，只有左标签可以退出了
				sb.append(origin.substring(i));
				i = j;
				break;
			}
			// 得到一个完整的标签名
			String tag = origin.substring(i + 1, j);
			if (isNeedEscape(tag, list, mode)) {
				sb.append("&lt;");
				sb.append(origin.substring(i + 1, j));
				sb.append("&gt;");
			} else {
				sb.append("<");
				sb.append(origin.substring(i + 1, j));
				sb.append(">");
			}

			i = j;
		}
		return sb.toString();
	}

	/**
	 * 字符串str前后标签是否需要过滤
	 * 
	 * @param str
	 * @param list
	 * @param mode
	 * @return
	 */
	static private boolean isNeedEscape(String str, List<String> list, int mode) {
		if (str.startsWith(MARK_DIVIDE)) {
			// </p>=>/p形式
			str = str.substring(1);
		}
		if (str.endsWith(MARK_DIVIDE)) {
			// <img/> => img/
			str = str.substring(0, str.length() - 1);
		}
		int idx = 0;
		if ((idx = str.indexOf(MARK_SPACE)) > -1) {
			// 有空格，那么可能是这种形式<img src=''/>
			str = str.substring(0, idx);
		}
		if (mode == MODE_BLACK) {
			if (list.contains(str))
				return true;
		}
		if (mode == MODE_WHITE) {
			if (!list.contains(str))
				return true;
		}
		return false;
	}

	public static void main(String[] args) {
		String origin = "<div><span>这是span</span><section>sec<></section><a href='http://www.baidu.com' /><img src='' /><script></script></div>";
		List<String> blackList = new ArrayList<>();
		blackList.add("a");
		blackList.add("img");
		blackList.add("script");
		String bl = escape(origin, blackList, MODE_BLACK);
		System.out.println(bl);
		List<String> whiteList = new ArrayList<>();
		whiteList.add("span");
		whiteList.add("div");
		String wl = escape(origin, whiteList, MODE_WHITE);
		System.out.println(wl);
		String esc = escape(origin);
		System.out.println(esc);
	}

	/***************** 以下方法实际是调用HttpServletRequest对应的方法（装饰者） ******************/
	@Override
	public Object getAttribute(String name) {
		return request.getAttribute(name);
	}

	@SuppressWarnings("rawtypes")
	@Override
	public Enumeration getAttributeNames() {
		return request.getAttributeNames();
	}

	@Override
	public String getCharacterEncoding() {
		return request.getCharacterEncoding();
	}

	@Override
	public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
		request.setCharacterEncoding(env);
	}

	@Override
	public int getContentLength() {
		return request.getContentLength();
	}

	@Override
	public String getContentType() {
		return request.getContentType();
	}

	@Override
	public ServletInputStream getInputStream() throws IOException {
		return request.getInputStream();
	}

	@SuppressWarnings("rawtypes")
	@Override
	public Enumeration getParameterNames() {
		return request.getParameterNames();
	}

	@Override
	public String[] getParameterValues(String name) {
		return request.getParameterValues(name);
	}

	@SuppressWarnings("rawtypes")
	@Override
	public Map getParameterMap() {
		return request.getParameterMap();
	}

	@Override
	public String getProtocol() {
		return request.getProtocol();
	}

	@Override
	public String getScheme() {
		return request.getScheme();
	}

	@Override
	public String getServerName() {
		return request.getServerName();
	}

	@Override
	public int getServerPort() {
		return request.getServerPort();
	}

	@Override
	public BufferedReader getReader() throws IOException {
		return request.getReader();
	}

	@Override
	public String getRemoteAddr() {
		return request.getRemoteAddr();
	}

	@Override
	public String getRemoteHost() {
		return request.getRemoteHost();
	}

	@Override
	public void setAttribute(String name, Object o) {
		request.setAttribute(name, o);
	}

	@Override
	public void removeAttribute(String name) {
		request.removeAttribute(name);
	}

	@Override
	public Locale getLocale() {
		return request.getLocale();
	}

	@SuppressWarnings("rawtypes")
	@Override
	public Enumeration getLocales() {
		return request.getLocales();
	}

	@Override
	public boolean isSecure() {
		return request.isSecure();
	}

	@Override
	public RequestDispatcher getRequestDispatcher(String path) {
		return request.getRequestDispatcher(path);
	}

	@SuppressWarnings("deprecation")
	@Override
	public String getRealPath(String path) {
		return request.getRealPath(path);
	}

	@Override
	public int getRemotePort() {
		return request.getRemotePort();
	}

	@Override
	public String getLocalName() {
		return request.getLocalName();
	}

	@Override
	public String getLocalAddr() {
		return request.getLocalAddr();
	}

	@Override
	public int getLocalPort() {
		return request.getLocalPort();
	}

	@Override
	public String getAuthType() {
		return request.getAuthType();
	}

	@Override
	public Cookie[] getCookies() {
		return request.getCookies();
	}

	@Override
	public long getDateHeader(String name) {
		return request.getDateHeader(name);
	}

	@Override
	public String getHeader(String name) {
		return request.getHeader(name);
	}

	@SuppressWarnings("rawtypes")
	@Override
	public Enumeration getHeaders(String name) {
		return request.getHeaders(name);
	}

	@SuppressWarnings("rawtypes")
	@Override
	public Enumeration getHeaderNames() {
		return request.getHeaderNames();
	}

	@Override
	public int getIntHeader(String name) {
		return request.getIntHeader(name);
	}

	@Override
	public String getMethod() {
		return request.getMethod();
	}

	@Override
	public String getPathInfo() {
		return request.getPathInfo();
	}

	@Override
	public String getPathTranslated() {
		return request.getPathTranslated();
	}

	@Override
	public String getContextPath() {
		return request.getContextPath();
	}

	@Override
	public String getQueryString() {
		return request.getQueryString();
	}

	@Override
	public String getRemoteUser() {
		return request.getRemoteUser();
	}

	@Override
	public boolean isUserInRole(String role) {
		return request.isUserInRole(role);
	}

	@Override
	public Principal getUserPrincipal() {
		return request.getUserPrincipal();
	}

	@Override
	public String getRequestedSessionId() {
		return request.getRequestedSessionId();
	}

	@Override
	public String getRequestURI() {
		return request.getRequestURI();
	}

	@Override
	public StringBuffer getRequestURL() {
		return request.getRequestURL();
	}

	@Override
	public String getServletPath() {
		return request.getServletPath();
	}

	@Override
	public HttpSession getSession(boolean create) {
		return request.getSession(create);
	}

	@Override
	public HttpSession getSession() {
		return request.getSession();
	}

	@Override
	public boolean isRequestedSessionIdValid() {
		return request.isRequestedSessionIdValid();
	}

	@Override
	public boolean isRequestedSessionIdFromCookie() {
		return request.isRequestedSessionIdFromCookie();
	}

	@Override
	public boolean isRequestedSessionIdFromURL() {
		return request.isRequestedSessionIdFromURL();
	}

	@Override
	public boolean isRequestedSessionIdFromUrl() {
		return request.isRequestedSessionIdFromURL();
	}

}
