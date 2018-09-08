package com.ajie.web.impl;

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

import com.ajie.chilli.utils.HttpClientUtil;
import com.ajie.chilli.utils.common.JsonUtil;
import com.ajie.chilli.utils.common.StringUtil;
import com.ajie.dao.pojo.TbUser;
import com.ajie.web.RemoteUserService;

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
	protected String ssoURL;

	public String getSsoUrl() {
		return ssoURL;
	}

	public void setSsoUrl(String ssoUrl) {
		this.ssoURL = ssoUrl;
	}

	@Override
	public TbUser getUserByToken(String token) throws IOException {
		if (null == ssoURL) {
			return null;
		}
		Map<String, String> param = new HashMap<String, String>();
		param.put("token", token);
		String loginURI = "user/getUserByToken.do";
		String url = ssoURL + loginURI;
		String result = HttpClientUtil.doGet(url, param);
		if (StringUtil.isEmpty(result)) {
			return null;
		}
		TbUser user = JsonUtil.toBean(result, TbUser.class);
		return user;
	}

	@Override
	public TbUser getUser(HttpServletRequest request) throws IOException {
		String token = getTokenByCookie(request);
		if (StringUtil.isEmpty(token)) {
			return null;
		}
		return getUserByToken(token);
	}

	@Override
	public boolean checkRoleForUrl(TbUser user, String url) throws IOException {
		if (null == user) {
			return false;
		}
		if (StringUtil.isEmpty(url)) {
			return false;
		}
		if (null == ssoURL) {
			return false;
		}
		String checkRoleRUI = "checkRole.do";
		String requrl = ssoURL + checkRoleRUI;
		Map<String, String> param = new HashMap<String, String>();
		param.put("user", user.getId() + "");
		param.put("url", url);
		String result = HttpClientUtil.doGet(requrl, param);
		if (null == result) {
			return false;
		}
		Map<String, Object> ret = JsonUtil.stringToCollect(result);
		return Boolean.valueOf(ret.get("ret").toString());
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
		for (Cookie cookie : cookies) {
			if (null == cookie)
				continue;
			if (RemoteUserService.USER_TOKEN.equals(cookie.getName())) {
				return cookie.getValue();
			}
		}
		return null;
	}

	@Override
	public void gotoLogin(HttpServletRequest req, HttpServletResponse res) throws IOException {
		StringBuffer refsb = req.getRequestURL();
		String query = req.getQueryString();
		String loginURI = "user/login.do";
		String url = ssoURL + loginURI;
		String ref = "";
		if (null != refsb) {
			ref = refsb.toString();
		}
		if (!StringUtil.isEmpty(query)) {
			try {
				ref += "%3f" + URLEncoder.encode(query, "utf-8");
			} catch (UnsupportedEncodingException e) {
				logger.warn("不支持utf-8字符编码转换" + query);
				ref = "%3fquery";
			}
		}
		Map<String, String> param = new HashMap<String, String>();
		param.put("ref", ref);
		HttpClientUtil.doGet(url , param);
	}

}
