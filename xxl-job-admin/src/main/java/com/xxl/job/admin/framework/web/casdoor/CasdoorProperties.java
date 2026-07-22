package com.xxl.job.admin.framework.web.casdoor;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Casdoor 对接配置（仅用于 admin 端验签 Stone 用 client_credentials 签发的 JWT）。
 * 配置来自新增的 casdoor.properties，不改动原 application.properties。
 */
@Component
@ConfigurationProperties(prefix = "casdoor")
public class CasdoorProperties {

	/** Casdoor 实例地址，如 https://casdoor.example.com */
	private String endpoint;

	/** Casdoor 应用 clientId（与 Stone 端 common-security 同一套） */
	private String clientId;

	/** Casdoor 应用 clientSecret */
	private String clientSecret;

	/** 回调地址（本期人类不登录 admin，预留） */
	private String redirectUri;

	/** Casdoor RSA 公钥 classpath 路径，如 classpath:cert/casdoor-public.key */
	private String publicKeyPath;

	/** admin 端 xxl_job_user 中对应的服务账号 username（由 Stone clientToken 代表） */
	private String serviceAccount;

	/** JWT issuer，验签时校验（与 Casdoor 实例一致）；为空则不强制校验 issuer */
	private String issuer;

	public String getEndpoint() {
		return endpoint;
	}

	public void setEndpoint(String endpoint) {
		this.endpoint = endpoint;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public String getPublicKeyPath() {
		return publicKeyPath;
	}

	public void setPublicKeyPath(String publicKeyPath) {
		this.publicKeyPath = publicKeyPath;
	}

	public String getServiceAccount() {
		return serviceAccount;
	}

	public void setServiceAccount(String serviceAccount) {
		this.serviceAccount = serviceAccount;
	}

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
}
