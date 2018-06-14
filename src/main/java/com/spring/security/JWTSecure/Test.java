package com.spring.security.JWTSecure;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Pattern;

import javax.crypto.NoSuchPaddingException;

class Test{
	public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, Exception {
		String value = "3q+O0X3TXDqTwPGjdxluii2FeQhoUl7AJH9wB8dOh9lzmN5r+BY5ID0i7eJ7gSAG+iXQfhARYTGk" + 
				"wp4FCS3pGFKSbprtJ3wQKsnhkIBYI0JcLFCcPn82pHrOHNsf5/Gy7a/0oFucnpUkyP+knJvcpUEH" + 
				"0Cb8XuGr4WUp3r6ac5FbZ2Cj0rbR7oouDn+w52GQdPN6J3YVrIKMl/lCRTGWig==";
		
		String JWT = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJqZXJyeSIsImV4cCI6MTUyOTc2NDQ5N30.NkX14Z1cNGNGosF_IJOSrCpeZ29Sb5VV71a5DlKzTrrUpxGT9C4Gowi8aMKTLtbxhJU76r0Bw4ed_j6ptuqg1g";
		
		System.out.println("Encrypt "+ CryptUtil.encrypt(JWT));
		System.out.println("==================================================");
		System.out.println("Value is " + value);
		
		System.out.println("Remove all from Encrypted " + CryptUtil.encrypt(JWT).replaceAll("\\r|\\n", ""));
		
		
		System.out.println("Match with patrern " + Pattern.compile("\\r|\\n").matcher(CryptUtil.encrypt(JWT)).find());
		
		System.out.println("Match with patrern " + Pattern.compile("\\r|\\n").matcher(CryptUtil.encrypt(JWT).replaceAll("\\r|\\n", "")).find());
		
		System.out.println(Pattern.compile("\\r|\\n").matcher(value).find());
	}
}