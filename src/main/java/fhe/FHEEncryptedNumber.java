package fhe;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

/**
 * @Classname FHEEncryptionNumber
 * @Description TODO
 * @Date 2022/4/6 16:37
 * @Created by 17402
 */
public class FHEEncryptedNumber implements Comparable{
    private static  int precision = 32;
    private BigInteger lv;
    private BigDecimal rv;
    private FHEContext context;
    private MathContext mathContext = new MathContext(precision);

    public FHEEncryptedNumber(){
        this.context=null;
    }


    public FHEEncryptedNumber(FHEContext context, BigInteger lv, BigDecimal rv){
        this.lv=lv;
        this.rv=rv.setScale(precision,BigDecimal.ROUND_HALF_EVEN);
        this.context=context;
    }
    public FHEEncryptedNumber(FHEContext context, BigInteger lv, double rv) {
        this.context = context;

        this.lv = lv;

        this.rv = new BigDecimal(rv).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
    }

    public FHEContext getContext() { return context; }

    public BigInteger getLV() {
        return lv;
    }

    public BigDecimal getRV() {
        return rv;
    }

  /*  public FHEEncryptedNumber add(FHEEncryptedNumber other) {
        return context.add(this, other);
    }

    public FHEEncryptedNumber add(double other) {
        return context.add(this, context.encrypt(other));
    }

    public FHEEncryptedNumber add(int other) {
        return context.add(this, context.encrypt(other));
    }*/
   public BigDecimal decrypt(FHEKey key) throws Exception {
       return key.decrypt(this).setScale(precision, BigDecimal.ROUND_HALF_EVEN);
   }

    public BigInteger decryptAsBigInteger(FHEKey key) throws Exception {
        BigDecimal realValue = key.decrypt(this);

        return realValue.toBigInteger();
    }

    public double decryptAsDouble(FHEKey key) throws Exception {
        BigDecimal realValue = key.decrypt(this).setScale(precision, BigDecimal.ROUND_HALF_EVEN);

        return realValue.doubleValue();
    }

    public long decryptAsLong(FHEKey key) throws Exception {
        double realValue = decryptAsDouble(key);

        return Math.round(realValue);
    }

    public int decryptAsInt(FHEKey key) throws Exception {
        double realValue = decryptAsDouble(key);

        return (int) Math.round(realValue);
    }
    public FHEEncryptedNumber add(FHEEncryptedNumber other) throws Exception {
        return context.add(this, other);
    }

    public FHEEncryptedNumber add(double other) throws Exception {
        return context.add(this, context.encrypt(other));
    }

    public FHEEncryptedNumber add(int other) throws Exception {
        return context.add(this, context.encrypt(other));
    }

    public FHEEncryptedNumber substract(FHEEncryptedNumber other) throws Exception {
       return context.subtract(this,other);
    }


    @Override
    public int compareTo(Object o) {
        if (o instanceof FHEEncryptedNumber) {

            FHEEncryptedNumber other = (FHEEncryptedNumber)o;

            return this.rv.compareTo(other.rv);
        }

        return 0;
    }
}
