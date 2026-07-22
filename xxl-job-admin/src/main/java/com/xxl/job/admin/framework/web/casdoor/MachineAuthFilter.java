package com.xxl.job.admin.framework.web.casdoor;

import com.xxl.job.admin.framework.model.XxlJobUser;
import com.xxl.sso.core.model.LoginInfo;
import com.xxl.tool.id.UUIDTool;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * 机器身份前置 Filter（位于 HeadlessAccessFilter 之后、XxlSsoWebInterceptor 之前）：
 *  - 仅拦截管理 JSON API（/jobinfo/**、/joblog/**、/jobgroup/**），其余路径原样放行
 *  - 从 {@code Authorization: Bearer <clientToken>} 取出 Casdoor clientToken
 *  - 用 CasdoorJwtVerifier 验签（RS256，与 Stone 端共用同一把公钥）
 *  - 用 CasdoorUserResolver 按配置的服务账号查/建 xxl_job_user
 *  - 将登录态直接写入 {@code request.setAttribute("xxl_sso_user", LoginInfo)}，
 *    业务控制器（JobInfoController.loginCheckWithAttr）据此判定已登录，无需 SSO Cookie
 *
 * 与“先换 SSO Cookie 再带 Cookie”的旧方案相比：无状态、无会话缓存、无过期重换，
 * 且天然规避了 session/create 验签失败的故障点。不改动任何原有源码。
 */
@Component
public class MachineAuthFilter implements Filter {

	private static final String LOGIN_ATTR = "xxl_sso_user";
	private static final String[] PROTECTED_PREFIXES = {"/jobinfo/", "/joblog/", "/jobgroup/"};

	private final CasdoorJwtVerifier jwtVerifier;
	private final CasdoorUserResolver userResolver;
	private final CasdoorProperties properties;

	@Autowired
	public MachineAuthFilter(CasdoorJwtVerifier jwtVerifier,
							 CasdoorUserResolver userResolver,
							 CasdoorProperties properties) {
		this.jwtVerifier = jwtVerifier;
		this.userResolver = userResolver;
		this.properties = properties;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		String path = request.getServletPath();

		// 仅管理 API 需要机器认证，其余（/api/** 执行器协议、/actuator/**、静态资源等）放行
		if (!isProtected(path)) {
			chain.doFilter(req, res);
			return;
		}

		String auth = request.getHeader("Authorization");
		if (auth == null || !auth.startsWith("Bearer ")) {
			sendUnauthorized(response, "missing or invalid Authorization header");
			return;
		}
		String jwt = auth.substring("Bearer ".length()).trim();

		// 1. 验签：非法调用方直接拒绝
		try {
			jwtVerifier.verifyAndGetSubject(jwt);
		} catch (Exception e) {
			sendUnauthorized(response, "invalid clientToken: " + e.getMessage());
			return;
		}

		// 2. 查/建 xxl_job_user（固定为配置的服务账号，Stone 已在自身侧完成 job:* 权限校验）
		XxlJobUser user = userResolver.resolve(properties.getServiceAccount());

		// 3. 将登录态写入请求上下文，等价于 SSO 登录后写入的 xxl_sso_user 属性
		LoginInfo loginInfo = new LoginInfo(String.valueOf(user.getId()), UUIDTool.getSimpleUUID());
		request.setAttribute(LOGIN_ATTR, loginInfo);

		chain.doFilter(req, res);
	}

	private boolean isProtected(String path) {
		for (String prefix : PROTECTED_PREFIXES) {
			if (path.startsWith(prefix)) {
				return true;
			}
		}
		return false;
	}

	private void sendUnauthorized(HttpServletResponse response, String msg) throws IOException {
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType("application/json;charset=UTF-8");
		response.getWriter().write("{\"code\":401,\"msg\":\"" + msg + "\"}");
	}
}
