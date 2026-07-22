package com.xxl.job.admin.framework.web.casdoor;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * 用 Casdoor RSA 公钥验签 Stone 用 client_credentials 签发的 JWT（RS256）。
 * 与 Stone 端 common-security 共用同一把 Casdoor 公钥 + 同一 JWT 标准，保持对 Stone 工程零代码耦合。
 */
@Component
public class CasdoorJwtVerifier {

	private final PublicKey publicKey;
	private final JwtParser parser;

	public CasdoorJwtVerifier(CasdoorProperties properties) throws Exception {
		this.publicKey = loadPublicKey(properties.getPublicKeyPath());

		JwtParserBuilder builder = Jwts.parser().verifyWith(this.publicKey);
		if (StringUtils.hasText(properties.getIssuer())) {
			builder.requireIssuer(properties.getIssuer());
		}
		this.parser = builder.build();
	}

	private PublicKey loadPublicKey(String path) throws Exception {
		String location = path;
		if (location.startsWith("classpath:")) {
			location = location.substring("classpath:".length());
		}
		try (InputStream is = new ClassPathResource(location).getInputStream()) {
			byte[] bytes = is.readAllBytes();
			String content = new String(bytes, StandardCharsets.UTF_8);

			if (content.contains("BEGIN CERTIFICATE")) {
				// X.509 证书格式：从证书中提取公钥
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				X509Certificate cert = (X509Certificate) cf.generateCertificate(
						new java.io.ByteArrayInputStream(bytes));
				return cert.getPublicKey();
			} else {
				// PEM 公钥格式：直接解析 RSA 公钥
				String base64 = content
						.replace("-----BEGIN PUBLIC KEY-----", "")
						.replace("-----END PUBLIC KEY-----", "")
						.replaceAll("\\s+", "");
				byte[] decoded = Base64.getDecoder().decode(base64);
				KeyFactory kf = KeyFactory.getInstance("RSA");
				return kf.generatePublic(new X509EncodedKeySpec(decoded));
			}
		}
	}

	/** 验签并返回 subject（调用方身份，通常为 clientId 或服务账号名）。非法 token 抛异常。 */
	public String verifyAndGetSubject(String jwt) {
		Jws<Claims> jws = parser.parseSignedClaims(jwt);
		return jws.getPayload().getSubject();
	}
}
