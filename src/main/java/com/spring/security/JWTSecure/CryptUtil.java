package com.spring.security.JWTSecure;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

@SuppressWarnings("restriction")
@Service
public class CryptUtil {
	
	
	public static final String ALGORITHM = "AES";
	public static String cryptKey;

	public static String encrypt(String plainString) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException ,Exception {
		Key key = generateKey();
		Cipher cipher = Cipher.getInstance(CryptUtil.ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedByteValue = cipher.doFinal(plainString.getBytes("utf-8"));
		String encryptedValue64 = new BASE64Encoder().encode(encryptedByteValue);
		return encryptedValue64;
	}

	public static String decrypt(String encryptedValue64) throws Exception {
		Key key = generateKey();
		Cipher cipher = Cipher.getInstance(CryptUtil.ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedValue64 = new BASE64Decoder().decodeBuffer(encryptedValue64);
		byte[] decryptedByteValue = cipher.doFinal(decryptedValue64);
		String decryptedValue = new String(decryptedByteValue, "utf-8");
		return decryptedValue;
	}

	public static Key generateKey() throws Exception {
		cryptKey = "1Hbfh667adgHCJ82";
		Key key = new SecretKeySpec(CryptUtil.cryptKey.getBytes(), CryptUtil.ALGORITHM);
		return key;
	}

	public static String md5Encrypt(String ticketNo) throws Exception {
			String generatedPassword = null;
			try {
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(ticketNo.getBytes());
				// Get the hash's bytes
				byte[] bytes = md.digest();
				// This bytes[] has bytes in decimal format;
				// Convert it to hexadecimal format
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < bytes.length; i++) {
					sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
				}
				// Get complete hashed password in hex format
				generatedPassword = sb.toString();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
		return generatedPassword;
	}
	
	/*public static void main(String[] args) {
		try {
			String password = "Summer2014";
			System.out.println("plain pass=" + password);
			String encryptedPassword = encrypt(password);
			System.out.println("encrypted pass=" + encryptedPassword);
			String decryptedPassword = decrypt(encryptedPassword);
			System.out.println("decrypted pass=" + decryptedPassword);
			
			String oneWayEncryptedPassword = md5Encrypt(password);
			System.out.println("oneWayEncryptedPassword  pass=" + oneWayEncryptedPassword);
			
		} catch (Exception e) {
			System.out.println("bug" + e.getMessage());
		}
	}*/
}
