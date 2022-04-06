package fhe;

import ch.obermuhlner.math.big.BigDecimalMath;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.util.Random;

/**
 * @Classname FHEContext
 * @Description TODO
 * @Date 2022/4/6 16:40
 * @Created by 17402
 */
public class FHEContext {
    private static final int precision=32;
    private Random rand=new Random();
    private FHEKey fheKey;
    private BigInteger encQ;
    private final int maxLoopCnt = 10000;
    private MathContext mathContext = new MathContext(precision);

    public FHEContext(FHEKey fheKey) throws  Exception{
        this.fheKey = fheKey;
    }
    public int getPrecision() {
        return precision;
    }


    public FHEContext() {

    }
    public FHEEncryptedNumber encrypt(long value) throws Exception {
        return encrypt((double)value);
    }
    public FHEEncryptedNumber encrypt(double value) throws Exception {
        FHEKey privateKey = fheKey;

        return encryptByPublicKey(value,privateKey);

    }
    //用私钥加密
    private FHEEncryptedNumber encryptByPublicKey(double value, FHEKey privateKey) throws Exception {

        try {
            int lowK = privateKey.getLowK();

            int highK = privateKey.getHighK();

            //k是密码中添加的随机扰动，k为有界正整数
            int k = rand.nextInt(highK - lowK + 1) + lowK;

            BigInteger lv= new BigInteger(privateKey.getRsaUtil().encryptByPublicKey(String.valueOf(k),privateKey.getRsaPublicKey().getEncoded()));

            BigDecimal rv = BigDecimalMath.pow(privateKey.ga(),(long)value,mathContext);

            rv = rv.multiply(new BigDecimal(value)).setScale(precision, BigDecimal.ROUND_HALF_EVEN);

            return new FHEEncryptedNumber(this, lv, rv);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }



}
