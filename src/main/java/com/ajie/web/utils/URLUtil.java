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
	 * 在urls是否有与url匹配的项，多通配符（可以有多个*）FIXME 还没完成
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
			int lastidx = pattern.lastIndexOf("*");
			if (idx == lastidx) // 单个*
				if (match(pattern, url))
					return true;
			// 多个 *
			String substring = pattern;
			while (idx != lastidx) {
				substring = pattern.substring(0, idx + 1);
				if (match(substring, url))
					return true;
				idx = pattern.indexOf("*", idx); // 下一个 * 号位置
			}
		}
		return false;
	}

	public static boolean match(String pattern, String url) {
		if (0 == url.compareTo(pattern)) // 全匹配
			return true;
		// 看看是否有通配符
		int idx = pattern.indexOf("*");
		if (idx == -1) // 没有通配符，全匹配
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
		}
		if (idx == pattern.length() - 1) { // xxx*
			pre = pattern.substring(0, idx);
			if (url.startsWith(pre))
				return true;
		}
		// 最后是 xxx*xxx形式
		pre = pattern.substring(0, idx);
		last = pattern.substring(idx + 1);
		if (url.startsWith(pre) && url.endsWith(last))
			return true;
		return false;
	}

	public static void main(String[] args) {
		List<String> urls = new ArrayList<String>() {
			private static final long serialVersionUID = 1L;
			{
				add("/user/user.do");
				add("*/menu.do");
				add("/nav/*.do");
				add("/blog/mine*");
			}
		};
		@SuppressWarnings("unused")
		boolean ret = URLUtil.match(urls, "/blog/mine.do");
		// System.out.println(ret);

		String str = "abcdezab";
		System.out.println(str.indexOf("z"));
		System.out.println(str.lastIndexOf("z"));
		System.out.println(str.substring(0, 1));
	}
}
