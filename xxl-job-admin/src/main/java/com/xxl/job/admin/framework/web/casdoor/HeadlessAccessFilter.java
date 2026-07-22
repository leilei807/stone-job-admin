package com.xxl.job.admin.framework.web.casdoor;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 无头封锁 Filter（最高优先级，位于 MachineAuthFilter / XxlSsoWebInterceptor 之前）：
 *  - 原生登录入口（/auth/login、/auth/doLogin、/auth/logout、/auth/updatePwd）一律 403，原生账号物理失效
 *  - 人类页面请求（Accept 含 text/html）一律 403
 *  - 放行 /api/**（执行器协议，由 OpenApiController 用 accessToken 校验）、/actuator/**（健康检查）
 *  - 管理 JSON API（/jobinfo/**、/joblog/**、/jobgroup/**）改由 MachineAuthFilter 用 clientToken 注入登录态，
 *    其余路径一律禁止人类访问
 *
 * 不改动任何原有源码；以纯 Servlet Filter 形态由 CasdoorSecurityAutoConfiguration 注册。
 */
public class HeadlessAccessFilter implements Filter {

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		// 放行判断基于 servletPath（不含 context-path），与 XxlSsoWebInterceptor.isMatchExcludedPaths 保持一致；
		// 否则在 context-path=/xxl-job-admin 下 getRequestURI() 为 /xxl-job-admin/api/...，会导致显式放行规则失效、只能靠兜底。
		String path = request.getServletPath();

		// 放行机器可访问的极小接口面（执行器协议 + 健康检查）
		if (path.startsWith("/api/")
				|| path.startsWith("/actuator/")) {
			chain.doFilter(req, res);
			return;
		}

		// 原生登录入口关闭
		if (path.startsWith("/auth/login")
				|| path.startsWith("/auth/doLogin")
				|| path.startsWith("/auth/logout")
				|| path.startsWith("/auth/updatePwd")) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "admin native login disabled");
			return;
		}

		// 人类页面（text/html）封锁
		String accept = request.getHeader("Accept");
		if (accept != null && accept.contains("text/html")) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, "headless mode: human access disabled");
			return;
		}

		// 其它（管理 JSON API 等）放行给后续 MachineAuthFilter / SSO 处理
		chain.doFilter(req, res);
	}
}
