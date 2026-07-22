package com.xxl.job.admin.framework.web.casdoor;

import jakarta.annotation.Resource;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.Ordered;

/**
 * 新增自动配置（不改动原 XxlSsoConfig）：
 *  - @PropertySource 加载 casdoor.properties
 *  - 以最高优先级注册 HeadlessAccessFilter（位于 XxlSsoWebInterceptor 之前，做无头封锁）
 *  - 次高优先级注册 MachineAuthFilter（位于 HeadlessAccessFilter 之后、SSO 拦截器之前，做机器 token 认证）
 */
@Configuration
@PropertySource("classpath:casdoor.properties")
public class CasdoorSecurityAutoConfiguration {

	@Resource
	private MachineAuthFilter machineAuthFilter;

	@Bean
	public FilterRegistrationBean<HeadlessAccessFilter> headlessAccessFilterRegistration() {
		FilterRegistrationBean<HeadlessAccessFilter> bean =
				new FilterRegistrationBean<>(new HeadlessAccessFilter());
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		bean.addUrlPatterns("/*");
		return bean;
	}

	@Bean
	public FilterRegistrationBean<MachineAuthFilter> machineAuthFilterRegistration() {
		FilterRegistrationBean<MachineAuthFilter> bean =
				new FilterRegistrationBean<>(machineAuthFilter);
		// 紧跟 HeadlessAccessFilter 之后，先于 XxlSsoWebInterceptor 执行
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
		bean.addUrlPatterns("/*");
		return bean;
	}
}
