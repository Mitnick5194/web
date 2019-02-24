package com.ajie.web.utils;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ajie.chilli.utils.common.StringUtils;

/**
 * Cookie 工具类
 * 
 * @author niezhenjie
 *
 */
public final class CookieUtils {

	public static final Logger logger = LoggerFactory.getLogger(CookieUtils.class);

	/**
	 * 获取cookie值，utf-8编码
	 * 
	 * @return
	 */
	public static String getCookieValue(HttpServletRequest req, String cookieName) {
		return getCookieValue(req, cookieName, "utf-8");
	}

	/**
	 * 获取cookie值，不编码
	 * 
	 * @param req
	 * @param cookieName
	 * @param cookieName
	 * @return
	 */
	public static String getCookieValueNotDecoder(HttpServletRequest req, String cookieName) {
		return getCookieValue(req, cookieName, null);
	}

	/**
	 * 获取cookie值，指定编码
	 * 
	 * @return
	 */
	public static String getCookieValue(HttpServletRequest req, String cookieName, String encode) {
		if (null == cookieName) {
			return null;
		}
		Cookie[] cookies = req.getCookies();
		if (null == cookies || cookies.length == 1)
			return null;
		String value = null;
		for (Cookie cookie : cookies) {
			if (StringUtils.eq(cookieName, cookie.getName())) {
				if (null != encode) {
					try {
						value = URLDecoder.decode(cookie.getValue(), encode);
					} catch (UnsupportedEncodingException e) {
						logger.warn("解码出错", e);
					}
				} else
					value = cookie.getValue();
				break;
			}
		}
		return value;
	}

	/**
	 * 使用默认 utf-8编码设置cookie，不指定过期时间
	 * 
	 * @param req
	 * @param res
	 * @param cookieName
	 */
	public static void setCookie(HttpServletRequest req, HttpServletResponse res, String name,
			String value) {
		setCookie(req, res, name, value, -1);
	}

	/**
	 * 使用默认 utf-8编码设置cookie，指定过期时间
	 * 
	 * @param req
	 * @param res
	 * @param cookieName
	 */
	public static void setCookie(HttpServletRequest req, HttpServletResponse res, String name,
			String value, int expiry) {
		setCookie(req, res, name, value, "utf-8", expiry);
	}

	/**
	 * 不指定编码，不指定过期时间
	 * 
	 * @param req
	 * @param res
	 * @param name
	 * @param value
	 */
	public static void setCookieNotDecoder(HttpServletRequest req, HttpServletResponse res,
			String name, String value) {
		setCookie(req, res, name, value, null);
	}

	/**
	 * 指定编码，不指定过期时间
	 * 
	 * @param req
	 * @param res
	 * @param name
	 * @param value
	 * @param decode
	 */
	public static void setCookie(HttpServletRequest req, HttpServletResponse res, String name,
			String value, String encode) {
		setCookie(req, res, name, value, encode, -1);
	}

	public static void setCookie(HttpServletRequest req, HttpServletResponse res, String name,
			String value, String encode, int expiry) {
		if (null == value)
			value = "";
		if (null != encode) {
			try {
				value = URLEncoder.encode(value, encode);
			} catch (UnsupportedEncodingException e) {
				logger.warn("编码出错", e);
			}
		}
		Cookie cookie = new Cookie(name, value);
		if (expiry > 0)
			cookie.setMaxAge(expiry);
		// 设置域名cookie
		String domain = getDomain(req);
		cookie.setDomain(domain);
		cookie.setPath("/"); // 使用根
		res.addCookie(cookie);
	}

	/**
	 * 获取请求的顶级（如果是二三级域名，需要作处理）域名
	 * 
	 * @param request
	 * @return
	 */
	private static String getDomain(HttpServletRequest request) {
		String domainName = null;
		String serverName = request.getRequestURL().toString();
		if (serverName == null || serverName.equals("")) {
			domainName = "";
		} else {
			serverName = serverName.toLowerCase();
			// 去除http://或者https://
			if (serverName.startsWith("http")) {
				serverName = serverName.substring(7);
			} else {
				serverName = serverName.substring(8);
			}
			// xxx.xxx.xxx/uri
			final int end = serverName.indexOf("/");
			// 去除uri部分
			serverName = serverName.substring(0, end);
			final String[] domains = serverName.split("\\.");
			int len = domains.length;
			if (len > 3) {
				// www.xxx.com.cn 设置后三层为域名
				domainName =  domains[len - 3] + "." + domains[len - 2] + "."
						+ domains[len - 1];
			} else if (len <= 3 && len > 1) {
				// xxx.com or xxx.cn
				domainName =  domains[len - 2] + "." + domains[len - 1];
			} else {
				domainName = serverName;
			}
		}
		// 去端口
		int portIdx = -1;
		if (domainName != null && (portIdx = domainName.indexOf(":")) > 0) {
			domainName = domainName.substring(0, portIdx);
		}
		return domainName;
	}

}
