package com.ajie.web.impl;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ajie.chilli.common.ResponseResult;
import com.ajie.chilli.utils.HttpClientUtil;
import com.ajie.chilli.utils.common.JsonUtils;
import com.ajie.chilli.utils.common.StringUtils;
import com.ajie.dao.pojo.TbUser;
import com.ajie.web.RemoteUserService;
import com.ajie.web.utils.CookieUtils;

/**
 * 远程用户服务实现
 * 
 * @author niezhenjie
 */
public class RemoteUserServiceImpl implements RemoteUserService {
	private static final Logger logger = LoggerFactory.getLogger(RemoteUserServiceImpl.class);

	/**
	 * sso系统链接
	 */
	protected String ssoBaseURL;

	/** sso系统的登录页面 */
	protected static final String login_uri = "user/loginpage.do";

	protected static final String token_uri = "user/getUserByToken.do";

	protected static final String role_uri = "user/checkRole.do";

	public void setSsoBaseURL(String ssoBaseURL) {
		synchronized (ssoBaseURL) {
			if (null == ssoBaseURL) {
				logger.error("找不到sso系统地址");
				return;
			}
			if (!ssoBaseURL.endsWith(File.separator)) {
				ssoBaseURL += File.separator;
			}
		}
		this.ssoBaseURL = ssoBaseURL;
	}

	public String getSsoBaseURL() {
		return ssoBaseURL;
	}

	@Override
	public TbUser getUserByToken(String token) throws IOException {
		if (null == ssoBaseURL) {
			return null;
		}
		Map<String, String> param = new HashMap<String, String>();
		param.put("token", token);
		String result = HttpClientUtil.doGet(ssoBaseURL + token_uri, param);
		if (StringUtils.isEmpty(result)) {
			return null;
		}
		ResponseResult response = JsonUtils.toBean(result, ResponseResult.class);
		if (response.getCode() != ResponseResult.CODE_SUC) {
			logger.error("远程调用sso系统token登录失败，token= " + token, "，失败原因: " + response.getMsg());
			return null;
		}
		TbUser user = (TbUser) response.getData();
		return user;
	}

	@Override
	public TbUser getUser(HttpServletRequest request) throws IOException {
		String token = getTokenByCookie(request);
		if (StringUtils.isEmpty(token)) {
			return null;
		}
		return getUserByToken(token);
	}

	@Override
	public boolean checkRoleForUrl(TbUser user, String url) throws IOException {
		if (null == user) {
			return false;
		}
		if (StringUtils.isEmpty(url)) {
			return false;
		}
		if (null == ssoBaseURL) {
			logger.error("找不到sso系统地址");
			return false;
		}
		Map<String, String> param = new HashMap<String, String>();
		param.put("user", user.getId() + "");
		param.put("url", url);
		String result = HttpClientUtil.doGet(ssoBaseURL + role_uri, param);
		if (null == result) {
			return false;
		}
		ResponseResult response = JsonUtils.toBean(result, ResponseResult.class);
		if (response.getCode() != ResponseResult.CODE_SUC) {
			logger.error("远程调用sso系统校验url权限失败，检测链接：" + url, "失败原因: " + response.getMsg());
			return false;
		}
		return (boolean) response.getData();
	}

	/**
	 * 从请求cookies中获取用户的token
	 * 
	 * @param request
	 * @return
	 */
	protected String getTokenByCookie(HttpServletRequest request) {
		Cookie[] cookies = request.getCookies();
		if (null == cookies || cookies.length == 0) {
			return null;
		}
		/*	for (Cookie cookie : cookies) {
				if (null == cookie)
					continue;
				if (RemoteUserService.USER_TOKEN.equals(cookie.getName())) {
					return cookie.getValue();
				}
			}*/
		String val = CookieUtils.getCookieValue(request, RemoteUserService.USER_TOKEN);
		return val;
	}

	@Override
	public void gotoLogin(HttpServletRequest req, HttpServletResponse res) throws IOException {
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
		res.sendRedirect(getSsoBaseURL() + login_uri + "?ref=" + ref);
	}
}
