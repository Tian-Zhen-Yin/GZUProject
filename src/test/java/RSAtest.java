import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
import rsa.*;
import util.BigIntegerUtil;
import util.HexUtil;
import util.Util;

import java.math.BigInteger;
import java.util.HashMap;

/**
 * @Classname RSAtest
 * @Description TODO
 * @Date 2022/4/7 0:20
 * @Created by 17402
 */
public class RSAtest {
  /*  @Test
    public void testRSAEncrypt(){
        RSAUtil rsaUtil=new RSAUtil();
        try {

            // 生成密钥对
            //KeyPair keyPair = getKeyPair();
            //String privateKey = new String(Base64.encodeBase64(keyPair.getPrivate().getEncoded()));
            //String publicKey = new String(Base64.encodeBase64(keyPair.getPublic().getEncoded()));
            //System.out.println("私钥 => " + privateKey + "\n");
            //System.out.println("公钥 =>" + publicKey + "\n");

            HashMap<String, String> keyPairMap = rsaUtil.getKeyPairMap(512);
            String privateKey = keyPairMap.get("privateKey");
            String publicKey =  keyPairMap.get("publicKey");
            System.out.println("私钥 => " + privateKey + "\n");
            System.out.println("公钥 =>" + publicKey + "\n");

            // RSA加密
            String data1 = "12";
            //String data = "123456111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
            String encryptData1 = rsaUtil.encrypt(data1, rsaUtil.getPublicKey(publicKey));
            String data2="12";
            String encryptData2 = rsaUtil.encrypt(data2, rsaUtil.getPublicKey(publicKey));
            BigInteger l1=new BigInteger(String.valueOf(Util.hexStringToAlgorism(HexUtil.byteArrayToHexStr(Base64.decodeBase64(encryptData1)))));
            BigInteger l2=new BigInteger(String.valueOf(Util.hexStringToAlgorism(HexUtil.byteArrayToHexStr(Base64.decodeBase64(encryptData2)))));
            BigInteger l3=l1.multiply(l2);
            System.out.println("加密前内容 => l1:" + Base64.decodeBase64(encryptData1)  + "\n");
            System.out.println("加密后内容 => " + l1  + "\n");
            System.out.println("加密后内容 => " + l2 + "\n");
            System.out.println("加密后内容 => " + l3 + "\n");
            //10进制转为16进制
            String sum= l3.toString(16);
            //16进制转为2进制
            String ensum= String.valueOf(Base64.encodeBase64(HexUtil.hexStrToByteArray(sum)));
            System.out.println("sum:"+ensum);
            // RSA解密
           // BigDecimal ec1=new BigDecimal(String.valueOf(Base64.decodeBase64(encryptData1)));
            System.out.println("ec1=>"+ rsaUtil.decrypt(encryptData1, rsaUtil.getPrivateKey(privateKey)));
            *//*String decryptData =rsaUtil.decrypt(String.valueOf(new BigDecimal(new BigInteger(Base64.decodeBase64(encryptData1))).multiply(new BigDecimal(encryptData2))), rsaUtil.getPrivateKey(privateKey));
            System.out.println("解密后内容 => " + decryptData + "\n");*//*



        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("RSA加解密异常");
        }

    }*/

    @Test
    public void testLongAndDouble(){
        double d = 0.1;
        long l = Math.round(d);
        System.out.println(l);

        long ll = 100L;
        double dd = (double) ll;
        System.out.println(dd);
    }

    @Test
    public void testBigIntDivide(){
        BigInteger bi1 = new BigInteger("999");
        BigInteger bi2 = new BigInteger("50");

        //public BigInteger add(BigInteger val):加
        System.out.println("add:"+bi1.add(bi2));

        //public BigInteger subtract(BigInteger val):减
        System.out.println("subtract:"+bi1.subtract(bi2));

        //public BigInteger multiply(BigInteger val):乘
        System.out.println("multiply:"+bi1.multiply(bi2));

        //public BigInteger divide(BigInteger val):除
        System.out.println("divide:"+bi1.divide(bi2));
    }

    @Test
    public void testRSAdIVISION(){
        RSAKeyGenerator keygen = new RSAKeyGenerator();
        RSACompleteKey completeKey = (RSACompleteKey)keygen.makeKey(RSAKey.COMPLETE_KEY);
        RSAPublicKey publicKey = (RSAPublicKey)keygen.makeKey(RSAKey.PUBLIC_KEY);
        RSAPrivateKey privateKey = (RSAPrivateKey)keygen.makeKey(RSAKey.PRIVATE_KEY);
        String m1="1321";
        BigInteger enc1=publicKey.encrypt(new BigInteger(m1));
        String m2="12";
        BigInteger enc2=publicKey.encrypt(new BigInteger(m2));
        BigInteger enc3=enc1.multiply(enc2);
        System.out.println(m1+"*"+m2+"="+privateKey.decrypt(enc3));
        BigInteger enc2In= BigIntegerUtil.modInverse(enc2,keygen.getModulus());
        BigInteger enc4=enc1.multiply(enc2In);
        BigInteger enc5=privateKey.decrypt(enc4);
        //模逆运算的前提是能整除。若不能整除，则无法解密
        System.out.println(m1+"/"+m2+"="+enc5);
    }
}
