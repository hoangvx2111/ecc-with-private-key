package com.example.ecc.main;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class EccWithPrivateKeyFile {

  public static void main(String[] args) {
    String plainText = "Hello World!";

    String path = getPath();

    System.out.println("Plaintext: " + plainText);
    File privatePem = new File(path + "\\private.key");
    File publicPem = new File(path + "\\public.pem");

    // Create two key pairs
    PrivateKey privateKey = readPrivateKey(privatePem);
    PublicKey publicKey = readPublicKey(publicPem);

    SecretKey key = generateSharedSecret(privateKey, publicKey);

    // Encrypt by secretKeyA
    String encryptText = encryptString(key, plainText);
    System.out.println("Encrypted text: " + encryptText);

    // Decrypt by secretKeyB
    String decryptedText = decryptString(key, encryptText);
    System.out.println("Decrypted text: " + decryptedText);

  }

  public static String getPath() {
    try {
      URL url = EccWithPrivateKeyFile.class.getClassLoader().getResource("key");
      File file = new File(URLDecoder.decode(url.getFile(), StandardCharsets.UTF_8));
      return file.getAbsolutePath();
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  public static SecretKey generateSharedSecret(PrivateKey privateKey,
                                               PublicKey publicKey) {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(publicKey, true);

      SecretKey keySpec = new SecretKeySpec(keyAgreement.generateSecret(), "AES");
      return keySpec;
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }
  }

  public static PrivateKey readPrivateKey(File file) {
    try {
      String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

      String privateKeyPEM = key
              .replace("-----BEGIN PRIVATE KEY-----", "")
              .replaceAll(System.lineSeparator(), "")
              .replace("-----END PRIVATE KEY-----", "");

      byte[] privateKey = Base64.decodeBase64(privateKeyPEM);

      return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privateKey));
    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException io) {
      io.printStackTrace();
      return null;
    }
  }

  public static PublicKey readPublicKey(File file) {
    try {
      String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

      String privateKeyPEM = key
              .replace("-----BEGIN PUBLIC KEY-----", "")
              .replaceAll(System.lineSeparator(), "")
              .replace("-----END PUBLIC KEY-----", "");
      byte[] publicKey = Base64.decodeBase64(privateKeyPEM);

      return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKey));
    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException io) {
      io.printStackTrace();
      return null;
    }
  }

  public static String encryptString(SecretKey key, String plainText) {
    try {
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] encryptByte = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
      return Base64.encodeBase64String(encryptByte);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | IllegalBlockSizeException | BadPaddingException e) {
      e.printStackTrace();
      return null;
    }
  }

  public static String decryptString(SecretKey key, String encryptText) {
    try {
      byte[] decode = Base64.decodeBase64(encryptText);
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

      cipher.init(Cipher.DECRYPT_MODE, key);
      byte[] decryptByte = cipher.doFinal(decode);
      String decryptText = new String(decryptByte);
      return decryptText;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
            | IllegalBlockSizeException | BadPaddingException e) {
      e.printStackTrace();
      return null;
    }
  }
}
