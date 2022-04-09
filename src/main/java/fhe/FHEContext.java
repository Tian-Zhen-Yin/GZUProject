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
    private MathContext mathContext = new MathContext(precision);

    public FHEContext(FHEKey fheKey) {
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
            //String lv=privateKey.getRsaUtil().encrypt(String.valueOf(k),privateKey.getRsaPublicKey());
            BigInteger lv=privateKey.getRsaPublicKey2().encrypt(new BigInteger(String.valueOf(k)));
            BigDecimal rv = BigDecimalMath.pow(privateKey.ga(),new BigDecimal(value),mathContext);

            rv = rv.multiply(new BigDecimal(k)).setScale(precision, BigDecimal.ROUND_HALF_EVEN);

            return new FHEEncryptedNumber(this, lv, rv);
        } catch (Exception e) {
            throw new Exception("加密出错");
        }

    }

    public FHEEncryptedNumber add(FHEEncryptedNumber op1,FHEEncryptedNumber op2) throws Exception{
        BigInteger lv;
        BigDecimal rv;

        BigInteger munLv=op1.getLV().multiply(op2.getLV());
        BigDecimal munRv=op1.getRV().multiply(op2.getRV());
        return new FHEEncryptedNumber(this,munLv,munRv);

    }
    public FHEEncryptedNumber subtract(FHEEncryptedNumber op1, FHEEncryptedNumber op2) throws Exception {
        BigInteger lv;
        BigDecimal rv;
        try {
            op2 = new FHEEncryptedNumber(this, op2.getLV(), op2.getRV().negate());
            return add(op1, op2);
        } catch (Exception e) {
            e.printStackTrace();
        }
        throw new Exception("加法失败");
    }


}
