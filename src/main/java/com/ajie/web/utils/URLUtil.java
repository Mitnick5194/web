package com.ajie.web.utils;

import java.util.ArrayList;
import java.util.List;

/**
 * 辅助url分析工具
 * 
 * @author niezhenjie
 */
public class URLUtil {

	private URLUtil() {
	}

	/**
	 * 在urls是否有与url匹配的项，单通配符（只能有一个*）
	 * 
	 * @param urls
	 *            规则列表
	 * @param url
	 *            校验uri
	 * @return
	 */
	public static boolean match(List<String> urls, String url) {
		if (null == url) {
			return false;
		}
		if (null == urls || urls.isEmpty()) {
			return false;
		}
		for (int i = 0, len = urls.size(); i < len; i++) {
			String pattern = urls.get(i);
			if (match(pattern, url)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 在urls是否有与url匹配的项，多通配符（可以有多个*）
	 * 
	 * @param urls
	 *            规则列表
	 * @param url
	 *            校验uri
	 * @return
	 */
	public static boolean matchs(List<String> urls, String url) {
		if (null == url) {
			return false;
		}
		if (null == urls || urls.isEmpty()) {
			return false;
		}
		for (int i = 0, len = urls.size(); i < len; i++) {
			String pattern = urls.get(i);
			int idx = pattern.indexOf("*");
			int lastIdx = pattern.lastIndexOf("*");
			if (idx == lastIdx) {// 单个*
				if (match(pattern, url))
					return true;
			} else { // 多个 *
				if (matchs(pattern, url)) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * 两个url单独作匹配
	 * 
	 * @param urls
	 *            规则列表
	 * @param url
	 *            校验uri
	 * @return
	 */
	public static boolean match(String pattern, String url) {
		if (0 == url.compareTo(pattern)) // 全匹配
			return true;
		// 看看是否有通配符
		int idx = pattern.indexOf("*");
		if (idx == -1) // 没有通配符
			return false;
		// 有通配符
		if (pattern.length() == 1) // *
			return true;
		String pre = ""; // 通配符前面部分
		String last = ""; // 通配符后面部分
		if (idx == 0) { // *xxx
			last = pattern.substring(idx + 1);
			if (url.endsWith(last))
				return true;
		} else if (idx == pattern.length() - 1) { // xxx*
			pre = pattern.substring(0, idx);
			if (url.startsWith(pre))
				return true;
		} else { // 最后是 xxx*xxx形式
			pre = pattern.substring(0, idx);
			last = pattern.substring(idx + 1);
			if (url.startsWith(pre) && url.endsWith(last))
				return true;
		}
		return false;
	}

	/**
	 * 两个url单独作匹配 ， 辅助多个* 匹配方法
	 * 
	 * @param urls
	 *            规则列表
	 * @param url
	 *            校验uri
	 * @return
	 */
	public static boolean matchs(String pattern, String url) {
		int idx = pattern.indexOf("*");
		int lastIdx = pattern.lastIndexOf("*");
		String start = pattern.substring(0, idx);
		String end = pattern.substring(lastIdx + 1);
		if (idx != 0) { // xxx*开头
			if (!url.startsWith(start))
				return false;
			else
				url = url.substring(start.length()); // 去除已经匹配过的部分
		}
		if (lastIdx + 1 != pattern.length()) { // *xxx结尾
			if (!url.endsWith(end)) {
				return false;
			} else {
				url = url.substring(0, url.length() - end.length()); // 去除已经匹配过的部分
			}
		}
		while (idx != lastIdx) {
			int nextIdx = pattern.indexOf("*", idx + 1);
			// *xxx*中间部分，即 xxx
			String match = pattern.substring(idx + 1, nextIdx);
			int matchIdx = url.indexOf(match);
			if (matchIdx == -1) {
				return false;
			}
			idx = nextIdx;
		}
		return true;
	}

	@SuppressWarnings("unused")
	public static void main(String[] args) {
		List<String> urls = new ArrayList<String>() {
			private static final long serialVersionUID = 1L;
			{
				add("/u*r/*.do/param/*");
				add("*/menu.do");
				add("/nav/*.do");
				add("/blog/mine*");
			}
		};
		boolean ret = URLUtil.match(urls, "/blog/mine.do");
		// System.out.println(ret);
		String str = "abcdezab";
		/*System.out.println(str.indexOf("z"));
		System.out.println(str.lastIndexOf("z"));
		System.out.println(str.substring(0, 1));*/
		/*String tex = "*_mine_*";
		String url = "aj_mine_order.do";*/
		/*int idx = str.lastIndexOf("b");
		System.out.println(idx);*/
		// System.out.println(str.substring(3));
		boolean res = URLUtil.matchs(urls, "/user/mine.do/param/oasdfp");
		boolean res1 = URLUtil.matchs(urls, "/user/mine1.do");
		System.out.println(res);
		System.out.println(res1);

	}
}
