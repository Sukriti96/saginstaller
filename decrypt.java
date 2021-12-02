package decrpt;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

public final class decrypt

{

	
	public static final void main(String[] args) throws Exception {
		
		
		String encryptedtext="kkkkk";
		String decryptedString=null;
		String errorMsg=null;
		
		try {
		    decryptedString = decrypt(encryptedtext,sidbiPrivateKey);
		} catch (NoSuchAlgorithmException e) {
			errorMsg=e.getMessage();
		} catch (InvalidKeyException e) {
			errorMsg=e.getMessage();
		} catch (IllegalBlockSizeException e) {
			errorMsg=e.getMessage();
		} catch (BadPaddingException e) {
			errorMsg=e.getMessage();
		} catch (NoSuchPaddingException e) {
			errorMsg=e.getMessage();
		} catch (IOException e) {
			errorMsg=e.getMessage();
		}
		
				
	}
	
	// --- <<IS-BEGIN-SHARED-SOURCE-AREA>> ---
	
	private static String sidbiPublicKey ="xxxx"; 
	private static String sidbiPrivateKey = "oooo";
	private static String idbiPublicKey = "yyyy";
	private static String idbiPrivateKey = "iiii";
	//private static String idbiPublicKey = "xxx";
	//private static String idbiPrivateKey = "xxxx";
		
	//Extracting Public Key
	public static PublicKey getPublicKey(String base64PublicKey){
	    PublicKey publicKey = null;
	    try{
	        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        publicKey = keyFactory.generatePublic(keySpec);
	        return publicKey;
	    } catch (NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    } catch (InvalidKeySpecException e) {
	        e.printStackTrace();
	    }
	    return publicKey;
	}
	
	//Extracting Private Key
	public static PrivateKey getPrivateKey(String base64PrivateKey){
	    PrivateKey privateKey = null;
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
	    KeyFactory keyFactory = null;
	    try {
	        keyFactory = KeyFactory.getInstance("RSA");
	    } catch (NoSuchAlgorithmException e) {
	        e.printStackTrace();
	    }
	    try {
	        privateKey = keyFactory.generatePrivate(keySpec);
	    } catch (InvalidKeySpecException e) {
	        e.printStackTrace();
	    }
	    return privateKey;
	}
	
	//Encrypting SIDBI Response
	public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
	    return cipher.doFinal(data.getBytes());
	}
	
	//Decrypting SIDBI Request
	public static String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
	    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	    cipher.init(Cipher.DECRYPT_MODE, privateKey);
	    return new String(cipher.doFinal(data));
	}
	
	public static String decrypt(String data, String base64PrivateKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
	    return decompressB64(decrypt(Base64.getDecoder().decode(data.getBytes()), getPrivateKey(base64PrivateKey)));
	}
	public static byte[] compress(String text) throws IOException {
	    return compress(text.getBytes());    }
	 
	public static byte[] compress(byte[] bArray) throws IOException {
	    ByteArrayOutputStream os = new ByteArrayOutputStream();      
	    try (DeflaterOutputStream dos = new DeflaterOutputStream(os)) {
	        dos.write(bArray);        }
	    return os.toByteArray();    }
	
	public static String decompressB64(String b64Compressed) throws IOException {
	    byte[] decompressedBArray = decompress(Base64.getDecoder().decode(b64Compressed));       
	    return new String(decompressedBArray, StandardCharsets.UTF_8);    }
	
	public static byte[] decompress(byte[] compressedTxt) throws IOException {
	    ByteArrayOutputStream os = new ByteArrayOutputStream();        
	    try (OutputStream ios = new InflaterOutputStream(os)) {
	        ios.write(compressedTxt);        }
	 
	    return os.toByteArray();    }
	
	public static String compressAndReturnB64(String text) throws IOException {
	    return new String(Base64.getEncoder().encode(compress(text)));    }
	
	
}