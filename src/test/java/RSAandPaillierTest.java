import fhe.FHEContext;
import fhe.FHEEncryptedNumber;
import fhe.FHEKey;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

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
        FHEKey fheKey=new FHEKey(1.014,16,100,10,512);
        FHEContext fheContext=new FHEContext(fheKey);
        double number = 10.1234;
        FHEEncryptedNumber enc1=fheContext.encrypt(number);
        log.info("encrypted 10.1234: " + enc1.toString());

        log.warn("After decrypt 10.1234 = " + String.valueOf(fheKey.decrypt(enc1)));
    }
}
