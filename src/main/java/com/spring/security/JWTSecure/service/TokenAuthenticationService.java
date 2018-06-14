package com.spring.security.JWTSecure.service;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Date;

import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.spring.security.JWTSecure.CryptUtil;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenAuthenticationService {

	static final long EXPIRATIONTIME = 864_000_000; // 10 days

	static final String SECRET = "@Pa55W0rD@";

	static final String TOKEN_PREFIX = "ScR@tch";

	static final String HEADER_STRING = "Authorization";

	public static void addAuthentication(HttpServletResponse res, String username) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, Exception {
		String JWT = Jwts.builder().setSubject(username)
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATIONTIME))
				.signWith(SignatureAlgorithm.HS512, SECRET).compact();
		res.addHeader(HEADER_STRING, CryptUtil.encrypt(JWT).replaceAll("\\r|\\n", ""));
	}

	public static Authentication getAuthentication(HttpServletRequest request) throws Exception {
		if(request.getHeader(HEADER_STRING)!=null && request.getHeader(HEADER_STRING).trim().length()>0) {
			String token = CryptUtil.decrypt(request.getHeader(HEADER_STRING));
			if (token != null) {
				String user = Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody().getSubject();
				return user != null ? new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList()) : null;
			}
		}
		return null;
	}
}
