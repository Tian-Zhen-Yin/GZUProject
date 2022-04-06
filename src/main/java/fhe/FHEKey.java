package fhe;

import ch.obermuhlner.math.big.BigDecimalMath;
import jpaillier.KeyPair;
import rsa.RSAUtil;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * @Classname FHEPrivateKey
 * @Description TODO
 * @Date 2022/4/6 15:35
 * @Created by 17402
 */
public class FHEKey {
    private int precision = 32;
    private  BigDecimal g;
    private int a;
    private int p;
    private  BigDecimal ga;
    private  int lowK;

    private  int highK;

    private Map<String, Object> keyMap;

    private int hashcode = 0;
    private RSAPrivateKey rsaPrivateKey;
    private RSAUtil rsaUtil;
    private RSAPublicKey rsaPublicKey;

    public interface Serializer {

        void serialize(int a,int p, int lowK, int highK,
                       BigDecimal g, int precision, RSAUtil rsaUtil, int hashcode) throws Exception;

        void serializeByRawData(int a,int p,int lowK, int highK,  BigDecimal g, int precision,
                                RSAUtil  rsaUtil, int hashcode) throws Exception;
    }
    public FHEKey(double g, int a, int lowK, int p, int keysize) throws Exception {
        try {
            this.g = new BigDecimal(g).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
            this.ga = this.g.pow(a).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
            this.a=a;
            this.p=p;
            this.lowK = lowK;
            this.highK = (p + 1) * lowK / p;
            this.rsaUtil=new RSAUtil();
            this.keyMap=RSAUtil.initKey(keysize);
            this.rsaPrivateKey=(RSAPrivateKey) keyMap.get("RSAPrivateKey");
            this.rsaPublicKey=(RSAPublicKey) keyMap.get("RSAPublicKey");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public BigDecimal decrypt(FHEEncryptedNumber value) throws Exception {

        try {

            int k = ByteBuffer.wrap(rsaUtil.decryptByPrivateKey(String.valueOf(value.getLV()),rsaPrivateKey.getEncoded())).getInt();

            BigDecimal rv = value.getRV();

            if (k == 0) {

            }
            BigDecimal lv=ga.pow(k).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
            return rv.divide(lv, precision, BigDecimal.ROUND_HALF_EVEN);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    BigDecimal ga() {
        return ga;
    }

    int getLowK() {
        return lowK;
    }

    int getHighK() {
        return highK;
    }
    RSAUtil getRsaUtil(){
        return rsaUtil;
    }
    RSAPublicKey getRsaPublicKey(){
        return rsaPublicKey;
    }
    RSAPrivateKey getRsaPrivateKey(){
        return rsaPrivateKey;
    }

    public void serialize(Serializer serializer, boolean useRawData) throws Exception {
        if (useRawData) {
            serializer.serializeByRawData(a, p, lowK, highK,g, precision, rsaUtil, hashCode());
        } else {
            serializer.serialize(a, p, lowK, highK, g, precision, rsaUtil, hashCode());
        }
    }

    @Override
    public int hashCode() {
        if (hashcode != 0) {
            return hashcode;
        }

        StringBuilder sb = new StringBuilder();
        sb.append(precision);
        sb.append(g.toBigInteger());
        sb.append(a);
        sb.append(p);
        sb.append(ga.toBigInteger());
        sb.append(lowK);
        sb.append(highK);
        sb.append(keyMap);
        sb.append(rsaPrivateKey);
        sb.append(rsaUtil);

        char[] charArr = sb.toString().toCharArray();
        for(char c : charArr) {
            hashcode = hashcode * 13 + c;
        }

        return hashcode;
    }

}
