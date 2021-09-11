package com.example.ecc.main;

import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

public class EccManagement {
  public static void main(String[] args) {
    String plainText = "Hello World!";

    System.out.println("Plaintext: " + plainText);

    // Create two key pairs
    KeyPair keyPairA = generateKeyPair();
    KeyPair keyPairB = generateKeyPair();

    // Create ECDH share secret by AES
    SecretKey secretKeyA = generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
    SecretKey secretKeyB = generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());

    System.out.println("Secret Key A: " + Base64.encodeBase64String(secretKeyA.getEncoded()).toUpperCase());
    System.out.println("Secret Key B: " + Base64.encodeBase64String(secretKeyB.getEncoded()).toUpperCase());

    // Encrypt by secretKeyA
    String encryptText = encryptString(secretKeyA, plainText);
    System.out.println("Encrypted text: " + encryptText);

    // Decrypt by secretKeyB
    String decryptedText = decryptString(secretKeyB, encryptText);
    System.out.println("Decrypted text: " + decryptedText);

  }

  public static KeyPair generateKeyPair() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "SunEC");
      ECGenParameterSpec parameterSpec = new ECGenParameterSpec("secp192k1");

      keyPairGenerator.initialize(parameterSpec);
      KeyPair keyPair = keyPairGenerator.genKeyPair();

      return keyPair;
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
            NoSuchProviderException e) {
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

  public static String encryptString(SecretKey key, String plainText) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, new byte[12]);

      cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
      byte[] encryptByte = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
      return Base64.encodeBase64String(encryptByte);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
            InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      e.printStackTrace();
      return null;
    }
  }

  public static String decryptString(SecretKey key, String encryptText) {
    try {
      byte[] decode = Base64.decodeBase64(encryptText);
      Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
      GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, new byte[12]);

      cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
      byte[] decryptByte = cipher.doFinal(decode);
      String decryptText = new String(decryptByte);
      return decryptText;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
            InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
      e.printStackTrace();
      return null;
    }
  }
}
