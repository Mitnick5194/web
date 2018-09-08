package com.ajie.web;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ajie.dao.pojo.TbUser;

/**
 * 远程用户服务接口
 * 
 * @author niezhenjie
 */
public interface RemoteUserService {

	/** cookie中token标识 */
	public static final String USER_TOKEN = "ut-ooo-nn";

	/**
	 * 通过token调用sso系统获取返回的User
	 * 
	 * @param token
	 * @return
	 * @throws IOException
	 */
	TbUser getUserByToken(String token) throws IOException;

	/**
	 * 通过request分析cookie取得token，再调用sso系统获取用户
	 * 
	 * @param request
	 * @return
	 * @throws IOException
	 */
	TbUser getUser(HttpServletRequest request) throws IOException;

	/**
	 * 用户是否有权限访问当前路径
	 * 
	 * @return
	 */
	boolean checkRoleForUrl(TbUser user, String url) throws IOException;

	/**
	 * 重定向到sso系统登录页面，登录成功后会回跳到当前链接
	 * 
	 * @param
	 * @throws IOException 
	 */
	void gotoLogin(HttpServletRequest req, HttpServletResponse res) throws IOException;

}
