package com.ppetric.sm;


import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class SM4Util {
	
	/**
	 * 不限明文长度的SM4加密
	 * 
	 * @param plaintext
	 * @param key
	 * @return
	 */
	public static byte[] encodeSMS4(byte[] plaintext, byte[] key) {
		int plainLen =(( plaintext.length +15 )/16)*16;
		
		byte[] plaintext16 = new byte[plainLen];//16位整数
		
		System.arraycopy(plaintext, 0, plaintext16, 0 , plaintext.length);
		
		
		byte[] ciphertext = new byte[plainLen]; 
		int k = 0;
		while (k + 16 <= plainLen) {
			byte[] cellPlain = new byte[16];
			for (int i = 0; i < 16; i++) {
				cellPlain[i] = plaintext16[k + i];
			}
			byte[] cellCipher = encode16(cellPlain, key);
			for (int i = 0; i < cellCipher.length; i++) {
				ciphertext[k + i] = cellCipher[i];
			}

			k += 16;
		}

		return ciphertext;
	}

	/**
	 * 不限明文长度的SM4解密
	 * 
	 * @param ciphertext
	 * @param key
	 * @return
	 */
	public static byte[] decodeSMS4(byte[] ciphertext, byte[] key) {
		byte[] plaintext = new byte[ciphertext.length];

		int k = 0;
		int cipherLen = ciphertext.length;
		while (k + 16 <= cipherLen) {
			byte[] cellCipher = new byte[16];
			for (int i = 0; i < 16; i++) {
				cellCipher[i] = ciphertext[k + i];
			}
			byte[] cellPlain = decode16(cellCipher, key);
			for (int i = 0; i < cellPlain.length; i++) {
				plaintext[k + i] = cellPlain[i];
			}

			k += 16;
		}

		return plaintext;
	}

	/**
	 * 解密，获得明文字符串
	 * 
	 * @param ciphertext
	 * @param key
	 * @return
	 */
	public static String decodeSMS4toString(byte[] ciphertext, byte[] key) {
		byte[] plaintext = new byte[ciphertext.length];
		plaintext = decodeSMS4(ciphertext, key);
		return new String(plaintext);
	}

	/**
	 * 只加密16位明文
	 * 
	 * @param plaintext
	 * @param key
	 * @return
	 */
	private static byte[] encode16(byte[] plaintext, byte[] key) {
		byte[] cipher = new byte[16];
		SM4 sm4 = new SM4();
		sm4.sms4(plaintext, 16, key, cipher,SM4.ENCRYPT);

		return cipher;
	}

	/**
	 * 只解密16位密文
	 * 
	 * @param plaintext
	 * @param key
	 * @return
	 */
	private static byte[] decode16(byte[] ciphertext, byte[] key) {
		byte[] plain = new byte[16];
		SM4 sm4 = new SM4();
		sm4.sms4(ciphertext, 16, key, plain, SM4.DECRYPT);

		return plain;
	}

	public static void main(String[] args) throws DecoderException {

		String hexData = "黄佳鹏";
		String hexKey = "11111111111111111111111111111111";
		byte[] enc = encodeSMS4(hexData.getBytes(), Hex.decodeHex(hexKey));
		System.out.println(Hex.encodeHexString(enc));


		String s = new String(decodeSMS4(enc, Hex.decodeHex(hexKey)));

		System.out.println(s);




	}
}