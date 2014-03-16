package com.keysofpeace.app.backend;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import org.spongycastle.crypto.CipherParameters;
import org.spongycastle.crypto.DataLengthException;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.util.encoders.Base64;

public class Crypto {
	final static String[] ALPHABETS_BITS_KEYS = { "Digits", "latin", "LATIN", "Punctuation" };

	final static String[] ALPHABETS_BITS_VALUES = { "23456789", "abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "~!@#$;%^:&?*()-+=[]{}\\|/<>,." };

	final static Charset CHARSET = Charset.forName("UTF-8");
	
	final static int IV_BITS_COUNT = 128;

	final static int HASH_BITS_COUNT = 256;

	final static int HASH_ITERATIONS_COUNT = 1000;

	final static int SALT_BITS_COUNT = 256;

	private static Crypto instance;
	
	PKCS5S2ParametersGenerator pbeParametersGenerator = new PKCS5S2ParametersGenerator(new SHA256Digest());

	PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

	SecureRandom random = new SecureRandom();

	public byte[] fromString(String string) {
		return Base64.decode(string);
	}

	public static Crypto getInstance() {
		if (null == Crypto.instance) {
			Crypto.instance = new Crypto();
		}
		return Crypto.instance;
	}

	public String encrypt(String string, byte[] key) throws CryptoException {
		byte[] salt = getSalt();
		cipher.reset();
		cipher.init(true, getCipherParameters(key, salt));
		byte[] bytes = string.getBytes(Crypto.CHARSET);
		byte[] ciphertext = new byte[cipher.getOutputSize(bytes.length)];
		int length = cipher.processBytes(bytes, 0, bytes.length, ciphertext, 0);
		try {
			length += cipher.doFinal(ciphertext, length);
		} catch (DataLengthException e) {
			throw new CryptoException("DataLengthException during encryption");
		} catch (IllegalStateException e) {
			throw new CryptoException("IllegalStateException during encryption");
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("InvalidCipherTextException during encryption");
		}
		if (ciphertext.length != length) {
			throw new CryptoException("Unexpected behaviour during encryption: getOutputSize value incorrect");
		}
		byte[] data = new byte[Crypto.SALT_BITS_COUNT / 8 + ciphertext.length];
		System.arraycopy(salt, 0, data, 0, Crypto.SALT_BITS_COUNT / 8);
		System.arraycopy(ciphertext, 0, data, Crypto.SALT_BITS_COUNT / 8, ciphertext.length);
		return toString(data);
	}

	public String decrypt(String dataString, byte[] key) throws CryptoException {
		byte[] data = fromString(dataString);
		byte[] salt = new byte[Crypto.SALT_BITS_COUNT / 8];
		System.arraycopy(data, 0, salt, 0, Crypto.SALT_BITS_COUNT / 8);
		cipher.reset();
		cipher.init(false, getCipherParameters(key, salt));
		byte[] temp = new byte[cipher.getOutputSize(data.length - Crypto.SALT_BITS_COUNT / 8)];
		int length = cipher.processBytes(data, salt.length, data.length - Crypto.SALT_BITS_COUNT / 8, temp, 0);
		try {
			length += cipher.doFinal(temp, length);
		} catch (DataLengthException e) {
			throw new CryptoException("DataLengthException during decryption");
		} catch (IllegalStateException e) {
			throw new CryptoException("IllegalStateException during decryption");
		} catch (InvalidCipherTextException e) {
			throw new CryptoException("InvalidCipherTextException during decryption");
		}
		byte[] bytes = new byte[length];
		System.arraycopy(temp, 0, bytes, 0, length);
		return new String(bytes, Crypto.CHARSET);
	}
	
	CipherParameters getCipherParameters(byte[] data, byte[] salt) {
		byte[] hash = this.hash(data, salt, Crypto.HASH_BITS_COUNT + Crypto.IV_BITS_COUNT);
		byte[] key = new byte[Crypto.HASH_BITS_COUNT / 8];
		byte[] iv = new byte[Crypto.IV_BITS_COUNT / 8];
		System.arraycopy(hash, 0, key, 0, Crypto.HASH_BITS_COUNT / 8);
		System.arraycopy(hash, Crypto.HASH_BITS_COUNT / 8, iv, 0, Crypto.IV_BITS_COUNT / 8);
		return new ParametersWithIV(new KeyParameter(key), iv);
	}

	public byte[] getSalt() {
		byte[] salt = new byte[Crypto.SALT_BITS_COUNT / 8];
		random.nextBytes(salt);
		return salt;
	}

	public byte[] hash(String string, byte[] salt) {
		return hash(string.getBytes(), salt);
	}

	public byte[] hash(byte[] bytes, byte[] salt) {
		return hash(bytes, salt, Crypto.HASH_BITS_COUNT);
	}

	public byte[] hash(byte[] bytes, byte[] salt, int bitsCount) {
		pbeParametersGenerator.init(bytes, salt, Crypto.HASH_ITERATIONS_COUNT);
		KeyParameter key = (KeyParameter) pbeParametersGenerator.generateDerivedMacParameters(bitsCount);
		return key.getKey();
	}

	public String toString(byte[] bytes) {
		return Base64.toBase64String(bytes);
	}
}
