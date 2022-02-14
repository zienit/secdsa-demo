package nl.zienit;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDFCounterBytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.gcm.GCMUtil;
import org.bouncycastle.crypto.params.KDFCounterParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Pack;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class PINBinder {

    private final static SecureRandom PRNG = new SecureRandom();
    private final static ECNamedCurveParameterSpec P_256 = ECNamedCurveTable.getParameterSpec("P-256");
    private final static BigInteger q = P_256.getN();
    private final static ECPoint G = P_256.getG();

    @BeforeClass
    public static void beforeClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private byte[] SHA256(byte[] M) {

        final var sha = new SHA256Digest();
        sha.update(M, 0, M.length);
        final var hash = new byte[sha.getDigestSize()];
        sha.doFinal(hash, 0);
        return hash;
    }

    // Appendix A
    // [As a building block we first define a key derivation function
    // deriving a key K(K,D,L) in the form of a byte array of size L bits based on
    // master key K and derivation byte array D.]
    private byte[] K(byte[] K, byte[] D, int L) {

        // NIST Special Publication 800-108
        // Recommendation for Key Derivation
        // Using Pseudorandom Functions
        // Section 5.1 KDF in Counter Mode

        final var L1 = (byte) ((L >> 8) & 0xff);
        final var L2 = (byte) (L & 0xff);

        final var fixedInputData = Arrays.copyOf(D, D.length + 3);
        fixedInputData[D.length] = 0x00;
        fixedInputData[D.length + 1] = L1;
        fixedInputData[D.length + 2] = L2;

        final var prf = new HMac(new SHA256Digest());
        final var kdf = new KDFCounterBytesGenerator(prf);

        // PRF (K, [i]2 || D || 0x00 || [L]2)
        final var params = new KDFCounterParameters(K, fixedInputData, 8);
        kdf.init(params);

        final var out = new byte[(int) Math.ceil(L / 8.0)];
        kdf.generateBytes(out, 0, out.length);
        return out;
    }

    // Algorithm 9 PIN-binder based on HMAC
    // Input: user PIN P , PIN-binder key: HMAC key K in SCE
    // Output: PIN-key σ
    private BigInteger PIN_binder_HMAC(byte[] PIN, byte[] K) {

        // Compute K(K,P,8∗|q|+64) and convert to integer x
        final var x = new BigInteger(1, K(K, PIN, q.bitLength() + 64));

        // 2: Return σ=1+(x mod (q−1))
        return BigInteger.ONE.add(x).mod(q.subtract(BigInteger.ONE));
    }

    @Test
    public void testPIN_binder_HMAC() throws Exception {

        final var K = "12345678901234567890123456789012".getBytes();
        final var PIN = "12345".getBytes();

        final var sigma = PIN_binder_HMAC(PIN, K);

        // PIN_binder is deterministic
        assertThat(sigma, equalTo(new BigInteger("2644a352b048ed1bd3a545ed74b576aad576c15ddabd0eda1d9abd849d438cbf", 16)));
    }

    public record ECIES_encrypted_message(ECPoint R, byte[] CT) {
    }

    // Alternative form of T = GMAC(K,IV,P,A) where
    // A = Ø
    // H = CIPHk(0)
    // J0 = GHASHh(IV || ...)
    // CIPHk_J0 = CIPHk(J0)
    // Meaning of symbols is defined in Algorithm 4 of NIST Special Publication 800-38D
    private byte[] GMAC(byte[] H, byte[] CIPHk_J0, byte[] P) {

        final var u = 16 * (int) Math.ceil(P.length / 16.0) - P.length;
        final var S_prep = Arrays.copyOf(P, P.length + u + 8 + 8);
        Pack.longToBigEndian((long) P.length * 8, S_prep, P.length + u + 8);
        final var S = GHASH.gHASH(H, S_prep);
        final var T = Arrays.copyOf(S, S.length);
        GCMUtil.xor(T, CIPHk_J0);
        return T;
    }

    // Algorithm 11 ECIES encryption based on AES-GCM
    // Input: Message M, recipient public key D.
    // Output: Ephemeral key R, AES-GCM ciphertext (C, T )
    private ECIES_encrypted_message ECIESe(byte[] M, ECPoint D) throws Exception {

        // 1: Select random k ∈ {1, ..., q − 1}.
        final var k = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        // 2: Compute R = k·G and Z = k·D // ephemeral key R
        final var R = G.multiply(k).normalize();
        final var Z = D.multiply(k).normalize();

        // Convert Z to byte array Z ̄ and compute H = SHA256(Z ̄)
        final var Z_dash = Z.getEncoded(false);
        final var H = SHA256(Arrays.copyOfRange(Z_dash, 1, Z_dash.length - 1));

        // Choose Initialisation Vector IV = H[0,15] and AES-GCM key K = H[16,31]
        final var IV = Arrays.copyOfRange(H, 0, 16);
        final var K = new SecretKeySpec(H, 16, 16, "AES");

        // 5: Compute hash-key HK = EAES(K,016) // AES-GCM
        // 6: Compute C = ECTR(IV, K, M)        // AES-GCM
        // 7: Compute T = GMAC(H, C)            // AES-GCM
        final var AES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        AES_GCM.init(Cipher.ENCRYPT_MODE, K, new GCMParameterSpec(128, IV));
        final var CT = AES_GCM.doFinal(M);

        return new ECIES_encrypted_message(R, CT);
    }

    // Algorithm 12 ECIES decryption based on AES-GCM
    // Input: Ephemeral key R, AES-GCM encrypted message (C, T ), recipient private key d.
    // Output: Message M or rejection of the encrypted message
    private byte[] ECIESd(ECPoint R, byte[] CT, BigInteger d) throws Exception {

        // 1: Compute Z = d·R.
        final var Z = R.multiply(d);

        // 2: Convert Z to byte array Z ̄ and compute H = SHA256(Z ̄)
        final var Z_dash = Z.getEncoded(false);
        final var H = SHA256(Arrays.copyOfRange(Z_dash, 1, Z_dash.length - 1));

        // 3: Choose Initialisation Vector IV = H[0,15] and AES-GCM key K = H[16,31]
        final var IV = new IvParameterSpec(Arrays.copyOfRange(H, 0, 16));
        final var K = new SecretKeySpec(Arrays.copyOfRange(H, 16, 32), "AES");

        // 4: Compute hash-key H = EAES(K,016)
        // 5: Compute T′ =GMAC(H,C) // AES-GCM
        // 6: If T′ ̸=T reject message // AES-GCM
        // 7: Compute M = DCTR(IV, K, C) // AES-GCM
        // 8: Return M
        final var AES_GCM = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        AES_GCM.init(Cipher.DECRYPT_MODE, K, new GCMParameterSpec(128, IV.getIV()));
        return AES_GCM.doFinal(CT);
    }

    @Test
    public void testECIES() throws Exception {

        final var d = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();
        final var D = G.multiply(d).normalize();

        final var M = "Squeamish Ossifrage".getBytes();

        final var enc = ECIESe(M, D);

        assertThat(ECIESd(enc.R, enc.CT, d), equalTo(M));
    }

    public record PIN_binder_context(ECPoint R, byte[] HK, byte[] AESk_J0, BigInteger d) {
    }

    // Algorithm 13 Generation of an ECIES-AES PIN-binder key in SCE
    private PIN_binder_context PIN_binder_ECIES_AES_generate() throws Exception {

        // 1: S-APP requests SCE to generate ECIES private key d ∈R F∗q // d in SCE
        final var d = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        // 2: S-APP exports public key D = d·G from SCE
        final var D = G.multiply(d);

        // 3: S-APP selects random k ∈ {1, ..., q − 1}.
        final var k = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        // 4: S-APP computes Z = k·D
        final var Z = D.multiply(k);

        // 5: S-APP converts Z to byte array Z¯ and compute H = SHA-256(Z¯)
        final var Z_dash = Z.getEncoded(false);
        final var H = SHA256(Arrays.copyOfRange(Z_dash, 1, Z_dash.length - 1));

        // 6: S-APP computes AES-GCM key K = H[16, 31]
        final var K = new SecretKeySpec(Arrays.copyOfRange(H, 16, 32), "AES");

        // 7: S-APP computes hash-key HK = EAES(K, 016) // AES-GCM
        final var AES = Cipher.getInstance("AES/ECB/NoPadding", "BC");
        AES.init(Cipher.ENCRYPT_MODE, K);
        final var HK = AES.doFinal(new byte[16]);

        // not in the paper: S-APP computes AESk(J0)
        final var IV = Arrays.copyOfRange(H, 0, 16);
        final var J0 = GHASH.J0(HK, IV);
        AES.init(Cipher.ENCRYPT_MODE, K);
        final var AESk_J0 = AES.doFinal(J0);

        // 8: S-APP locally stores R and HK and deletes Z and K
        final var R = G.multiply(k);
        return new PIN_binder_context(R, HK, AESk_J0, d);
    }

    // Algorithm 14 PIN-binder based on ECIES-AES
    // Input: user PIN P, PIN-binder key: HMAC key K, R, H, AESk_J0, ECIES private key d (in SCE)
    // Output: PIN-key σ
    private BigInteger PIN_binder_ECIES_AES(byte[] PIN, byte[] K, ECPoint R, byte[] H, byte[] AESk_J0, BigInteger d) throws Exception {

        // 1: Compute P = K(K, P, 8 ∗ |q| + 64)
        final var P = K(K, PIN, q.bitLength() + 64);

        // 2: Compute authentication tag T = GMAC(H, P)
        final var T = GMAC(H, AESk_J0, P);

        // 3: Feed R, (P, T) to Algorithm 12 resulting in P' // ECIES decrypt
        final var P_concat_T = Arrays.copyOf(P, P.length + T.length);
        System.arraycopy(T, 0, P_concat_T, P.length, T.length);
        final var P_accent = ECIESd(R, P_concat_T, d);

        // 4: Convert P' to integer x // same byte length 8 ∗ |q| + 64
        final var x = new BigInteger(1, P_accent);

        // 5: Return σ = 1 + (x mod (q − 1))
        return BigInteger.ONE.add(x).mod(q.subtract(BigInteger.ONE));
    }

    @Test
    public void testPIN_binder_ECIES_AES() throws Exception {

        final var ctx = PIN_binder_ECIES_AES_generate();

        final var K = "12345678901234567890123456789012".getBytes();
        final var PIN = "12345".getBytes();

        final var sigma = PIN_binder_ECIES_AES(PIN, K, ctx.R, ctx.HK, ctx.AESk_J0, ctx.d);

        System.out.println(sigma.toString(16));
    }
}
