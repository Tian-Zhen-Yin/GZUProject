import fhe.FHEContext;
import fhe.FHEEncryptedNumber;
import fhe.FHEKey;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @Classname RSAandPaillierTest
 * @Description TODO
 * @Date 2022/4/6 23:34
 * @Created by 17402
 */
@Slf4j
public class RSAandPaillierTest {

    @Test
    public void testSWHEEncrypt() throws Exception {
        FHEKey fheKey = new FHEKey(1.014, 16, 100, 10, 512);
        FHEContext fheContext = new FHEContext(fheKey);
        double number = 12.34;
        FHEEncryptedNumber enc1 = fheContext.encrypt(number);
        log.info("encrypted 12.34: " + enc1.toString());

        log.warn("After decrypt 12.34 = " + String.valueOf(fheKey.decrypt(enc1)));
    }

    @Test
    public void testSWHEEncryptSum() throws Exception {
        FHEKey fheKey = new FHEKey(1.014, 16, 100, 10, 512);

        double number = 10.1234;
        double m = 53266210.747972414;
        double n = 12341.2345;

        int p=100;
        int q=10;

        FHEContext context = new FHEContext(fheKey);

        FHEEncryptedNumber enc1 = context.encrypt(m);
        log.warn("After encrypt:m="+enc1);
        FHEEncryptedNumber enc2 = context.encrypt(q);
        log.warn("After encrypt:q="+enc2);
        log.warn("Before encrypt:");
        FHEEncryptedNumber sum = context.add(enc1, enc2);
        log.warn("Before encrypt:p-q="+(p-q));
        FHEEncryptedNumber enc3=context.encrypt(p);
        FHEEncryptedNumber sub = context.subtract(enc3, enc2);
        int decSub=sub.decryptAsInt(fheKey);
        log.warn("After decrypt p-q = " + String.valueOf(decSub));
        //int decSum = sum.decryptAsInt(fheKey);

       // log.warn("After decrypt m + n = " + String.valueOf(decSum));

    }

    public static List<Integer> getIntegerList(String path) {
        List<Integer> list = new ArrayList<Integer>();
        try {
            FileReader fileReader = new FileReader(path);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String str = null;
            while ((str = bufferedReader.readLine()) != null) {

                list.add(Integer.parseInt(str));

            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return list;
    }

    /*读取浮点型数据*/
    public static List<Float> getFloatList(String path) {
        List<Float> list = new ArrayList<Float>();
        try {
            FileReader fileReader = new FileReader(path);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String str = null;
            while ((str = bufferedReader.readLine()) != null) {
                list.add(Float.parseFloat(str));
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return list;
    }

    /**
     * 测试读取文件
     */
    @Test
    public void testReadFile(){
        List<Integer> smallNums = getIntegerList("src/main/resources/random_small_int_num_list.txt");
        System.out.println(smallNums.size());
    }
    @Test
    public void testSmallIntEncrypt() throws Exception {
        FHEKey fheKey = new FHEKey(1.014, 16, 100, 10, 512);
        FHEContext context = new FHEContext(fheKey);
        List<Integer> smallNums = getIntegerList("src/main/resources/random_small_int_num_list.txt");
        long start;
        long end;
        System.out.println(smallNums.size());

        //250 0000整数加密测试
        start = System.currentTimeMillis();
        List<FHEEncryptedNumber> encSmallIntNum1Lists = smallNums.parallelStream().map(value -> {
            try {
                return context.encrypt(value);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end = System.currentTimeMillis();
        log.info("250 0000 small int numbers encrypt: elapse time is " + String.valueOf((end - start)));

        //250 0000整数解密测试
        start = System.currentTimeMillis();
        List<Integer> decodedSmallInt = encSmallIntNum1Lists.parallelStream().map(num -> {
            try {
                return num.decryptAsInt(fheKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end = System.currentTimeMillis();
        log.info("250 0000 small int numbers decrypt: elapse time is " + String.valueOf((end - start)));
    }
    @Test
    public void testSmallFloatEncrypt() throws Exception {
        FHEKey fheKey = new FHEKey(1.014, 16, 100, 10, 512);
        FHEContext context = new FHEContext(fheKey);
        List<Float> smallFloatNums = getFloatList("src/main/resources/random_small_float_num_list.txt");
        long start;
        long end;
        start=System.currentTimeMillis();
        List<FHEEncryptedNumber> encSmallFloatNum1Lists = smallFloatNums.parallelStream().map(value -> {
            try {
                return context.encrypt(value);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end=System.currentTimeMillis();
        log.info("250 0000 small float numbers encrypt: elapse time is " + String.valueOf((end - start)));


        start=System.currentTimeMillis();
        List<Double> decodedSmallFloat = encSmallFloatNum1Lists.parallelStream().map(num -> {
            try {
                return num.decryptAsDouble(fheKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end=System.currentTimeMillis();
        log.info("250 0000 small float numbers decrypt: elapse time is " + String.valueOf((end - start)));
    }

    @Test
    public void testBigIntEncryption() throws Exception {
        FHEKey fheKey = new FHEKey(1.014, 16, 100, 10, 512);
        FHEContext context = new FHEContext(fheKey);
        List<Integer> bigNums = getIntegerList("src/main/resources/random_big_int_num_list.txt");
        log.info("Before encrypt");
        long start;
        long end;
        start=System.currentTimeMillis();
        List<Integer> bigNms=bigNums.subList(0,100);
        List<FHEEncryptedNumber> encBigIntNum1Lists = bigNms.parallelStream().map(value -> {
            try {
                return context.encrypt(value);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end =System.currentTimeMillis();
        log.info("100 big int numbers encrypt: elapse time is " + String.valueOf((end - start)));


        start=System.currentTimeMillis();
        List<Integer> decodedBigInt = encBigIntNum1Lists.parallelStream().map(num -> {
            try {
                return num.decryptAsInt(fheKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end=System.currentTimeMillis();
        log.info("100 big int numbers decrypt: elapse time is " + String.valueOf((end - start)));
    }
    @Test
    public void testBigFloatEncryption() throws Exception {
        FHEKey fheKey = new FHEKey(1.014, 16, 100, 10, 512);
        FHEContext context = new FHEContext(fheKey);
        List<Float> bigFloatNums = getFloatList("src/main/resources/random_big_float_num_list.txt");
        long start;
        long end;
        List<Float> bigFloatnNum=bigFloatNums.subList(0,100);
        start = System.currentTimeMillis();
        List<FHEEncryptedNumber> encBigFloatNum1Lists = bigFloatnNum.parallelStream().map(value -> {
            try {
                return context.encrypt(value);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end =System.currentTimeMillis();
        log.info("100 big float numbers encrypt: elapse time is " + String.valueOf((end - start)));



        //250 0000大整数解密测试
        start=System.currentTimeMillis();
        List<Double> decodedBigFloat = encBigFloatNum1Lists.parallelStream().map(num -> {
            try {
                return num.decryptAsDouble(fheKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }).collect(Collectors.toList());
        end=System.currentTimeMillis();
        log.info("100 big float numbers decrypt: elapse time is " + String.valueOf((end - start)));
    }


    @Test
    public void testNewHEEncrypt() throws Exception {

        FHEKey fheKey = new FHEKey(1.014, 16, 100, 10, 512);
        FHEContext context = new FHEContext(fheKey);
        List<Integer> smallNums = getIntegerList("src/main/resources/random_small_int_num_list.txt");
        long start,end;

        //250万的小整数和250万的大整数混合加减混合运算
        //250万次加法运算
        // List<>
        //end=System.currentTimeMillis();
        //250万的小浮点数和250万的大浮点数混合加减混合运算

        start=System.currentTimeMillis();
        end=System.currentTimeMillis();

        //125万小整数，125万大整数，125万小浮点数，125万大浮点数加减混合运算
        start=System.currentTimeMillis();
        end=System.currentTimeMillis();


    }


}
