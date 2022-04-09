import org.apache.commons.codec.binary.Base64;
import org.junit.Test;
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
}
