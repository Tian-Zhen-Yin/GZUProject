package rsa;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAUtil {



        //非崔晨加密算法
        private static final String KEY_ALGORITHM = "RSA";
        //公钥
        private static final String PUBLIC_KEY = "RSAPublicKey";
        //私钥
        private static final String PRIVATE_KEY = "RSAPrivateKey";
        private static final int MAX_ENCRYPT_BLOCK = 117;

        private static final int MAX_DECRYPT_BLOCK = 128;


    /**
         * 私钥解密
         *
         * @param data 待解密数据
         * @param key  私钥
         * @return byte[] 解密数据
         * @throws Exception
         */
        public  byte[] decryptByPrivateKey(String data, byte[] key) throws Exception {
            byte[] dataBytes= Base64.decodeBase64(data);
            //取得私钥
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            //生成私钥
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            //对数据解密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            int inputLen=dataBytes.length;
            ByteArrayOutputStream out=new ByteArrayOutputStream();
            int offset=0;
            byte[] cache;
            int i=0;

            while (inputLen - offset > 0) {
                if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                    cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
                } else {
                    cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
                }
                out.write(cache, 0, cache.length);
                i++;
                offset = i * MAX_ENCRYPT_BLOCK;
            }
            byte[] encryptedData = out.toByteArray();
            out.close();

            return encryptedData;
        }

/*
        */
/**
         * 公钥解密
         *
         * @param data 待解密数据
         * @param key  公钥
         * @return byte[] 解密数据
         * @throws Exception
         *//*

        public  byte[] decryptByPublicKey(byte[] data, byte[] key) throws Exception {
            //取得公钥
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            //生成公钥
            PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
            //对数据解密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return cipher.doFinal(data);
        }
*/

       /* *//**
         * 私钥加密
         *
         * @param data 待加密数据
         * @param key  私钥
         * @return byte[] 加密数据
         * @throws Exception
         *//*
        public  byte[] encryptByPrivateKey(byte[] data, byte[] key) throws Exception {
            //取得私钥
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            //生成私钥
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8KeySpec);
            //对数据加密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(data);
        }
*/
        /**
         * 公钥加密
         *
         * @param data 待加密数据
         * @param key  公钥
         * @return byte[] 加密数据
         * @throws Exception
         */
        public  byte[] encryptByPublicKey(String data, byte[] key) throws Exception {
            byte[] encryptedData=Base64.decodeBase64(data);
            //取得公钥
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            //生成密钥
            PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
            //加密数据
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(encryptedData);
        }

        /**
         * 取得私钥
         *
         * @param keyMap 私钥Map
         * @return byte[] 私钥
         * @throws Exception
         */
        public  byte[] getPrivateKey(Map<String, Object> keyMap) throws Exception {
            Key key = (Key) keyMap.get(PRIVATE_KEY);
            return key.getEncoded();
        }

        /**
         * 取得公钥
         *
         * @param keyMap 公钥Map
         * @return byte[] 公钥
         * @throws Exception
         */
        public  byte[] getPublicKey(Map<String, Object> keyMap) throws Exception {
            Key key = (Key) keyMap.get(PUBLIC_KEY);
            return key.getEncoded();
        }

        /**
         * 初始化密钥
         *
         * @return Map 密钥Map
         * @throws Exception
         */
        public static Map<String, Object> initKey(int KEY_SIZE) throws Exception {
            //实例化密钥对生成器
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
            //初始化密钥对生成器
            keyPairGenerator.initialize(KEY_SIZE);
            //生成密钥对
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            //私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            //封装密钥
            Map<String, Object> keyMap = new HashMap<String, Object>(2);
            keyMap.put(PUBLIC_KEY, publicKey);
            keyMap.put(PRIVATE_KEY, privateKey);
            return keyMap;
        }



}
