package fhe;

import ch.obermuhlner.math.big.BigDecimalMath;
import rsa.RSAKey;
import rsa.RSAKeyGenerator;
import rsa.RSAPrivateKey;
import rsa.RSAPublicKey;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;

/**
 * @Classname FHEPrivateKey
 * @Description TODO
 * @Date 2022/4/6 15:35
 * @Created by 17402
 */
public class FHEKey {
    byte PUBLIC_KEY = 1;
    byte PRIVATE_KEY = 2;
    private int precision = 32;
    private  BigDecimal g;
    private int a;
    private int p;
    private  BigDecimal ga;
    private  int lowK;

    private  int highK;
    private BigInteger n;

    private HashMap<String, String> keyMap;

    private int hashcode = 0;
    private PrivateKey rsaPrivateKey;
    private PublicKey rsaPublicKey;
    private RSAKeyGenerator rsaKeyGenerator;
    private RSAPrivateKey rsaPrivateKey2;
    private RSAPublicKey rsaPublicKey2;
    private MathContext mathContext = new MathContext(precision);
    public interface Serializer {

        void serialize(int a,int p, int lowK, int highK,
                       BigDecimal g, int precision,   int hashcode) throws Exception;

        void serializeByRawData(int a,int p,int lowK, int highK,  BigDecimal g, int precision
                                  , int hashcode) throws Exception;
    }
    public FHEKey(double g, int a, int lowK, int p, int keysize) throws Exception {
        try {
            this.g = new BigDecimal(g).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
            this.ga = this.g.pow(a).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
            this.a=a;
            this.p=p;
            this.lowK = lowK;
            this.highK = (p + 1) * lowK / p;
       /*     this.keyMap=RSAUtil.getKeyPairMap(keysize);
            this.rsaPrivateKey= rsaUtil.getPrivateKey(keyMap.get("privateKey"));
            this.rsaPublicKey= rsaUtil.getPublicKey(keyMap.get("publicKey")) ;*/
            this.rsaKeyGenerator=new RSAKeyGenerator();
            this.n=rsaKeyGenerator.getModulus();
            this.rsaPrivateKey2= (RSAPrivateKey) rsaKeyGenerator.makeKey(PRIVATE_KEY);
            this.rsaPublicKey2=(RSAPublicKey) rsaKeyGenerator.makeKey(PUBLIC_KEY);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public BigDecimal decrypt(FHEEncryptedNumber value) throws Exception {

        try {


                int k = rsaPrivateKey2.decrypt(value.getLV()).intValue() ;

                BigDecimal rv = value.getRV();

                //BigDecimal rv=ga.pow(0.1/a).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
                BigDecimal rv1=rv.divide(BigDecimal.valueOf(k),BigDecimal.ROUND_HALF_EVEN);
                double ta=  (a*1.0);
                double y=1/ta;
                BigDecimal rv2=BigDecimalMath.pow(rv1, new BigDecimal(y),mathContext);
                BigDecimal frv=BigDecimalMath.log2(rv2,mathContext).divide(BigDecimalMath.log2(g,mathContext),BigDecimal.ROUND_HALF_EVEN);
                return frv;


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
    PublicKey getRsaPublicKey(){
        return rsaPublicKey;
    }
    PrivateKey getRsaPrivateKey(){
        return rsaPrivateKey;
    }
    BigInteger getN(){
        return n;
    }
    RSAKeyGenerator getRsaKeyGenerator(){return rsaKeyGenerator;}
    RSAPrivateKey getRsaPrivateKey2(){return rsaPrivateKey2;}
    RSAPublicKey getRsaPublicKey2(){return rsaPublicKey2;}

    public void serialize(Serializer serializer, boolean useRawData) throws Exception {
        if (useRawData) {
            serializer.serializeByRawData(a, p, lowK, highK,g, precision,  hashCode());
        } else {
            serializer.serialize(a, p, lowK, highK, g, precision, hashCode());
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
        sb.append(rsaPrivateKey2);
        sb.append(rsaPublicKey2);

        char[] charArr = sb.toString().toCharArray();
        for(char c : charArr) {
            hashcode = hashcode * 13 + c;
        }

        return hashcode;
    }

}
