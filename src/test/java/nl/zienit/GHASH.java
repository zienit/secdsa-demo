package nl.zienit;

import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.util.Pack;

// This code is published as part of an answer to a stackoverflow question.
// For more information please see https://stackoverflow.com/questions/53046729/can-i-decrypt-gcm-aes-stream-in-bouncy-castle-using-anything-having-skippingciph?rq=1
// The code is slightly adapted for the ECIES PIN-binder use case.
public class GHASH {

    // AES block size in bytes.
    private static final int AES_BLOCK_SIZE = 16;

    // Default (recommended) GCM IV size.
    private static final int GCM_DEFAULT_IV_SIZE = 12;

    // Perform 'inc32' operation on CTR counter.
    public static byte inc32(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                return 0;
            }
        }
        return 1;
    }

    // Get GCM gHASH function result.
    private static void gHASHPartial(
            final GCMMultiplier multiplier, byte[] Y, byte[] b, int off, int len) {
        GCMUtil.xor(Y, b, off, len);
        multiplier.multiplyH(Y);
    }

    // Get GCM gHASH function result.
    private static void gHASHBlock(
            final GCMMultiplier multiplier, byte[] Y, byte[] b) {
        GCMUtil.xor(Y, b);
        multiplier.multiplyH(Y);
    }

    // Get GCM gHASH function result.
    private static void gHASH(
            final GCMMultiplier multiplier, byte[] Y, byte[] b, int len) {
        for (int pos = 0; pos < len; pos += AES_BLOCK_SIZE)
        {
            final int num = Math.min(len - pos, AES_BLOCK_SIZE);
            gHASHPartial(multiplier, Y, b, pos, num);
        }
    }

    public static byte[] gHASH(final byte[] H, byte[] b) {
        final GCMMultiplier multiplier = new Tables4kGCMMultiplier();
        multiplier.init(H);
        final byte [] S = new byte[AES_BLOCK_SIZE];
        gHASH(multiplier, S, b, b.length);
        return S;
    }

    // Convert GCM initialization vector into appropriate CTR one
    // so our CTR-based 'GCM decryptor' works.
    // This is based on Bouncy Castle GCM block cipher implementation
    // in accordance with NIST 800-38D Nov 2007 document.
    public static byte[] J0(
            final byte [] H,
            byte[] gcmIv) {

        final byte [] J0 = new byte[AES_BLOCK_SIZE];
        if (gcmIv.length == GCM_DEFAULT_IV_SIZE) {

            // In case of 12 bytes IV everything is simple.
            System.arraycopy(gcmIv, 0, J0, 0, gcmIv.length);
            J0[AES_BLOCK_SIZE - 1] = 0x01;

        } else {

            // For other sizes it is much more complex.

            // We need to init GCM multiplier based on given
            // (already initialized) AES cipher.
            // Pay attention GCMMultiplier tables don't change
            // unless the key changes.
//            final byte [] H = new byte[AES_BLOCK_SIZE];
//            aes.processBlock(H, 0, H, 0);

            final GCMMultiplier multiplier = new Tables4kGCMMultiplier();
            multiplier.init(H);

            final byte [] nonce = new byte[AES_BLOCK_SIZE];
            System.arraycopy(gcmIv, 0, nonce, 0, gcmIv.length);

            gHASH(multiplier, J0, nonce, nonce.length);
            final byte[] X = new byte[AES_BLOCK_SIZE];
            Pack.longToBigEndian((long)gcmIv.length * 8, X, 8);
            gHASHBlock(multiplier, J0, X);
        }
        //inc32(J0);
        return J0;
    }
}
