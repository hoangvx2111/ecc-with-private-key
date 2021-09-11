package com.example.ecc.main;


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class KeyGenerator {

  private static final byte[] CRLF = new byte[] {'\r', '\n'};

  public static String generateKey(String name) {
    try {
      StringBuilder sb = new StringBuilder();

      KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
      kpg.initialize(256);
      KeyPair kp = kpg.generateKeyPair();

      if (name.contains("private")) {
        sb.append("-----BEGIN PRIVATE KEY-----" + System.lineSeparator())
                .append(Base64.getMimeEncoder(64, CRLF).encodeToString(kp.getPrivate().getEncoded()) + System.lineSeparator())
                .append("-----END PRIVATE KEY-----");
        System.out.println();
      } else if (name.contains("public")) {
        sb.append("-----BEGIN PUBLIC KEY-----" + System.lineSeparator())
                .append(Base64.getMimeEncoder(64, CRLF).encodeToString(kp.getPublic().getEncoded()) + System.lineSeparator())
                .append("-----END PUBLIC KEY-----");
      }

      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return null;
    }
  }
}
