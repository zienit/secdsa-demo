package nl.zienit;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * Unit test for simple App.
 */
public class SECDSA {

    private final static SecureRandom PRNG = new SecureRandom();
    private final static ECNamedCurveParameterSpec P_256 = ECNamedCurveTable.getParameterSpec("P-256");
    private final static BigInteger q = P_256.getN();
    private final static ECPoint G = P_256.getG();

    private record ECDSASignature(BigInteger r, BigInteger s) {
    }

    private byte[] H(byte[] M) {

        final var sha = new SHA256Digest();
        sha.update(M, 0, M.length);
        final var hash = new byte[sha.getDigestSize()];
        sha.doFinal(hash, 0);
        return hash;
    }

    // Algorithm 1 ECDSA signature generation
    // Input: message M, private key u
    // Output signature (r, s).
    private ECDSASignature ECDSASignatureGeneration(byte[] M, BigInteger u) {

        // 1: Compute H(M) and convert this to an integer e.
        final var e = new BigInteger(1, H(M));

        return rawECDSASignatureGeneration(e, u);
    }

    private ECDSASignature rawECDSASignatureGeneration(BigInteger e, BigInteger u) {

        // 2: Select random k ∈ {1, ..., q − 1}.
        final var k = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        // 3: Compute kG = (x, y) and convert x to integer x ̄.
        // 4: Compute r=x ̄mod q. If r=0 go to Line 1.
        final var r = G.multiply(k).normalize().getXCoord().toBigInteger().mod(q);

        // 5: If r mod q=0 then go to Line 1.
        assertThat(r, not(equalTo(0)));

        // 6: Compute s=k−1(e+u·r) mod q. If s=0 go to Line 1.
        final var s = k.modInverse(q).multiply(e.add(u.multiply(r).mod(q))).mod(q);

        // 7: Return (r,s).
        return new ECDSASignature(r, s);
    }

    // Algorithm 2 ECDSA signature verification
    // Input: message M, signature (r,s), public key U
    // Output: Acceptance of rejection of the signature.
    private boolean ECDSASignatureVerification(byte[] M, BigInteger r, BigInteger s, ECPoint U) {

        // 1: Verify that r,s are integers in interval [1,q−1]. On failure reject the signature.
        assertThat(r, greaterThan(BigInteger.ZERO));
        assertThat(r, lessThan(q));
        assertThat(s, greaterThan(BigInteger.ZERO));
        assertThat(s, lessThan(q));

        // 2: Compute H(M) and convert this to an integer e.
        final var e = new BigInteger(1, H(M));

        // 3: Compute w = s−1 mod q.
        final var w = s.modInverse(q);

        // 4: Compute t1 =e·w mod q and t2 =r·w mod q.
        final var t1 = e.multiply(w).mod(q);
        final var t2 = r.multiply(w).mod(q);

        // 5: Compute X=t1·G+t2·U.
        final var X = G.multiply(t1).add(U.multiply(t2)).normalize();

        // 6: If X = O reject the signature.
        assertThat(X.isInfinity(), equalTo(false));

        // 7: Convert the x-coordinate of X to an integer x ̄; compute v = x ̄ mod q.
        final var v = X.getXCoord().toBigInteger().mod(q);

        // 8: If v = r accept the signature otherwise reject it
        return v.equals(r);
    }

    @Test
    public void testECDSA() {

        final byte[] M = "foobar".getBytes();

        final var u = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();
        final var U = G.multiply(u);

        final var signature = ECDSASignatureGeneration(M, u);

        final var accepted = ECDSASignatureVerification(M, signature.r, signature.s, U);

        assertThat(accepted, equalTo(true));
    }

    // Algorithm 3 Alternative ECDSA signature verification
    // Input: message M, signature (R,s), public key U
    // Output: Acceptance of rejection of the signature.
    private boolean fullECDSASignatureVerification(byte[] M, ECPoint R, BigInteger s, ECPoint U) {

        // 1: Verify that O ≠ R ∈ ⟨G⟩ and that s is integer in interval [1,q − 1]. On failure reject the signature.
        assertThat(R.isInfinity(), equalTo(false));
        assertThat(s, greaterThan(BigInteger.ZERO));
        assertThat(s, lessThan(q));

        // 2: Compute H(M) and convert this to an integer e.
        final var e = new BigInteger(1, H(M));

        // 3: Compute w = s−1 mod q.
        final var w = s.modInverse(q);

        // 4: Convert the x-coordinate of R to an integer r ̄; compute r = r ̄ mod q.
        final var r = R.getXCoord().toBigInteger().mod(q);

        // 5: Compute G′ =wG and U′ =wU
        final var G_accent = G.multiply(w);
        final var U_accent = U.multiply(w);

        // 6: Compute X = eG′ + rU′.
        final var X = G_accent.multiply(e).add(U_accent.multiply(r)).normalize();

        // 7: If X = R accept the signature otherwise reject it
        return X.equals(R);
    }

    private ECPoint fullECDSASignatureTransformation(BigInteger e, ECDSASignature signature, ECPoint U) {

        // Proof: Suppose one possesses a valid signature (r,s) on message M. Then it
        // follows that (X,s) is a valid full ECDSA signature where X is as in Line 5
        // of Algorithm 2.

        // 3: Compute w = s−1 mod q.
        final var w = signature.s.modInverse(q);

        // 4: Compute t1 =e·w mod q and t2 =r·w mod q.
        final var t1 = e.multiply(w).mod(q);
        final var t2 = signature.r.multiply(w).mod(q);

        // 5: Compute X=t1·G+t2·U.
        return G.multiply(t1).add(U.multiply(t2)).normalize();
    }

    // Proposition 2.1 Let Y be an ECDSA public key and M a message, then the following
    // are equivalent:
    // 1. One possesses a valid ECDSA signature (r,s) on message M.
    // 2. One possesses a valid full ECDSA signature (R,s) on message M.
    @Test
    public void testProposition2_1() {

        final var y = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();
        final var Y = G.multiply(y);

        final byte[] M = "foobar".getBytes();

        final var e = new BigInteger(1, H(M));
        final var signature = rawECDSASignatureGeneration(e, y);

        final var R = fullECDSASignatureTransformation(e, signature, Y);

        final var accepted = fullECDSASignatureVerification(M, R, signature.s, Y);

        assertThat(accepted, equalTo(true));
    }

    private record Transcript(BigInteger r, BigInteger s) {
    }

    // Algorithm4 DTc(V→d E|D=d·U,A)
    // Creation of transcript by holder of a private key d and binding to byte array A.
    // [see also https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic]
    private Transcript DTc(ECPoint V, BigInteger d, ECPoint U, byte[] A) {

        // 1: Select random k ∈ {1, ..., q − 1}.
        final var k = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        // 2: Compute k·U, k·V (i = 1,...,n), and convert to byte arrays U ̄,V ̄.
        final var U_bar = U.multiply(k).getEncoded(false);
        final var V_bar = V.multiply(k).getEncoded(false);

        // 3: Compute byte array H(U ̄||V ̄||A) of size |q| and convert it to integer r
        final var buffer = new byte[U_bar.length + V_bar.length + A.length - 2];
        System.arraycopy(U_bar, 1, buffer, 0, U_bar.length - 1);
        System.arraycopy(V_bar, 1, buffer, U_bar.length - 1, V_bar.length - 1);
        System.arraycopy(A, 0, buffer, buffer.length - A.length, A.length);

        final var r = new BigInteger(1, H(buffer));

        // 4: If r = 0 then go to Line 1.
        assertThat(r, not(equalTo(0)));

        // 5: Compute s=k+r·d mod q.
        final var s = k.add(r.multiply(d)).mod(q);

        // 6: If s = 0 then go to Line 1.
        assertThat(s, not(equalTo(0)));

        // 7: Return (r,s).
        return new Transcript(r, s);
    }

    // Algorithm 5 DTv(V,E,DT ,D,A)
    // Verification of transcript DT = (r, s) by verifier using public key D = d·U .
    private boolean DTv(ECPoint V, ECPoint E, Transcript DT, ECPoint D, ECPoint U, byte[] A) {

        // 1: Verify that V, E ∈ G on failure Return False.
        assertThat(V.isValid(), equalTo(true));
        assertThat(E.isValid(), equalTo(true));

        // 2: Verify that r ∈ {1, 2^8·|q| − 1} and s ∈ {1, q − 1}, on failure Return False.
        final var r_upper = BigInteger.TWO.pow(q.bitLength());
        assertThat(DT.r, greaterThan(BigInteger.ZERO));
        assertThat(DT.r, lessThan(r_upper));

        // 3: Compute Q1 =s·U−r·D, Q2 =s·V −r·E
        final var Q1 = U.multiply(DT.s).subtract(D.multiply(DT.r));
        final var Q2 = V.multiply(DT.s).subtract(E.multiply(DT.r));

        // 4: if Q1 =O or Q2 =O Return False.
        assertThat(Q1.isInfinity(), equalTo(false));
        assertThat(Q2.isInfinity(), equalTo(false));

        // 5: Convert Q1 , Q2 to byte arrays Q ̄1 , Q ̄2 .
        final var Q1_bar = Q1.getEncoded(false);
        final var Q2_bar = Q2.getEncoded(false);

        // 6: Compute byte array H(Q ̄1||Q ̄2||A) of size |q| and convert it to integer v.
        final var buffer = new byte[Q1_bar.length + Q2_bar.length + A.length - 2];
        System.arraycopy(Q1_bar, 1, buffer, 0, Q1_bar.length - 1);
        System.arraycopy(Q2_bar, 1, buffer, Q1_bar.length - 1, Q2_bar.length - 1);
        System.arraycopy(A, 0, buffer, buffer.length - A.length, A.length);

        final var v = new BigInteger(1, H(buffer));

        // 7: If v = r Return True otherwise Return False.
        return v.equals(DT.r);
    }

    @Test
    public void testZPK() {

        final var U = G.multiply(new BigInteger("1234"));
        final var V = G.multiply(new BigInteger("5678"));

        final var d = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();
        final var D = U.multiply(d);
        final var E = V.multiply(d);

        final var A = "foobar".getBytes();

        final var DT = DTc(V, d, U, A);

        final var accepted = DTv(V, E, DT, D, U, A);

        assertThat(accepted, equalTo(true));
    }

    // Algorithm 6 Split-ECDSA (SECDSA) signature generation
    // Input: message M, SCE-key u ∈ F∗q, PIN-key σ ∈ F∗q
    // Output signature (r, s).
    // [Changed input M to e]
    private ECDSASignature splitECDSASignatureGeneration(BigInteger e, BigInteger u, BigInteger sigma) {

        // 1: Compute H(M) and convert this to an integer e.

        // 2: Compute e′ = σ−1·e mod q
        final var e_accent = sigma.modInverse(q).multiply(e).mod(q);

        // 3: Select random k∈{1,...,q−1}
        // 4: Compute kG = (x, y) and convert x to integer x ̄
        // 5: Compute r=x ̄modq. If r=0 go to Line 1
        // 6: If r mod q=0 then go to Line 1
        // 7: Compute s=k−1(e′ +u·r) mod q. If s=0 go to Line 1
        final var signature = rawECDSASignatureGeneration(e_accent, u);

        // 8: Compute s′ = σ·s mod q
        final var s_accent = sigma.multiply(signature.s).mod(q);

        // 9: Return (r,s′)
        return new ECDSASignature(signature.r, s_accent);
    }

    @Test
    // Proposition 3.1 Algorithm 6 returns an ECDSA signature (r,s) on message
    // M based on the private key u·σ mod q, i.e. the product of the SCE-key u and the
    // PIN-key σ.
    public void testProposition3_1() {

        final var u = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();
        final var sigma = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        final var M = "foobar".getBytes();

        final var e = new BigInteger(1, H(M));
        final var signature = splitECDSASignatureGeneration(e, u, sigma);

        // public key Y = u·σ·G
        final var Y = G.multiply(u).multiply(sigma);

        final var accepted = ECDSASignatureVerification(M, signature.r, signature.s, Y);

        assertThat(accepted, equalTo(true));
    }

    private record Certificate(String Id, ECPoint Y_accent, byte[] hashedCId) {
    }

    private record CertificateIssuance(byte[] CId, Certificate C, Transcript DT) {
    }

    private class CertificateIssuer {

        private final BigInteger a;

        public CertificateIssuer(BigInteger a) {
            this.a = a;
        }

        public CertificateIssuance certificateIssuance(String Id, ECPoint Y) {

            // 5: CI generates an array of |q| random bytes CId (certificate identifier)
            final var CId = new byte[q.bitLength() / 8];
            PRNG.nextBytes(CId);

            // 6: CI computes Y′ = a·Y. // encryption of Y
            final var Y_accent = Y.multiply(a);

            // 7: CI generate ZKP DT =DT(Y→a Y′|G′ =a·G) // G′ is ZKP-public key
            // The zero-knowledge proof DT in Line 7 allows the user/S-APP to validate
            // that Y′ is correctly formed, i.e. as in Line 6.
            final var DT = DTc(Y, a, G, new byte[0]);

            // 8: CI generates certificate C based on Id,Y′,H(CId)
            final var C = new Certificate(Id, Y_accent, H(CId));

            // 9: CI sends CId, C, DT, to User
            return new CertificateIssuance(CId, C, DT);
        }
    }

    private record SigSF(byte[] H, ECPoint R, ECPoint S_accent, ECPoint S_double_accent, BigInteger N, Transcript DT1) {
    }

    private record SigRP(SigSF SigSF, ECPoint R_accent, Transcript DT2) {
    }

    private class SigningFacilitator {

        private final BigInteger a;
        private final ECPoint G_accent;
        // 'session state'
        private BigInteger N;
        private Certificate C;
        private RelyingParty RP;

        public SigningFacilitator(BigInteger a) {
            this.a = a;
            G_accent = G.multiply(a);
        }

        public BigInteger setupSession(byte[] CId, Certificate C, RelyingParty RP) {
            // 4: SF verifies certificate C // correctly signed not revoked
            // 5: SF computes H(CId) and verifies that certificate C is based on it
            assertThat(C.hashedCId, equalTo(H(CId)));

            // 6: SF looks up PIN-counter for certificate C, on failure initialises one
            // 7: SF checks if PIN-counter exceeds threshold, if so returns Error to S-APP
            // 8: SF validates C, on success sends random nonce N to S-APP
            this.C = C;
            this.RP = RP;
            N = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();
            return N;
        }

        public void verify(SigSF SigSF) {

            // 22: SF verifies DT1 on S′, S′′, G′, Y′, N on failure returns Error to S-APP
            // Cf. Algorithm 5, nonce N from Line 8
            assertThat(N, equalTo(this.N));

            assertThat(DTv(G_accent, SigSF.S_accent, SigSF.DT1, SigSF.S_double_accent, C.Y_accent, N.toByteArray()), equalTo(true));

            // 23: SF converts the x-coordinate of R to integer r ̄; computes r = r ̄ mod q
            final var r = SigSF.R.getXCoord().toBigInteger().mod(q);

            // 24: SF converts H to integer e
            final var e = new BigInteger(1, SigSF.H);

            // 25: SF computes R′ = a·R
            final var R_accent = SigSF.R.multiply(a);

            // 26: Verify if R′ = e·S′ + r·S′′
            //    On failure, SF increments PIN-counter with 1, returns Error to S-APP
            //    On success, SF resets PIN-counter to 0
            assertThat(R_accent, equalTo(SigSF.S_accent.multiply(e).add(SigSF.S_double_accent.multiply(r))));

            // 27: SF generates ZKP DT2 =DT(R→a R′|G′ =a·G,N) // Link ZKP to N
            final var DT2 = DTc(SigSF.R, a, G, N.toByteArray());

            // 28: SF sends signature SigRP = {SigSF,R′,DT2} to RP
            // mechanism depends on use case, cf. Section 4
            final var SigRP = new SigRP(SigSF, R_accent, DT2);

            // use case: Centralized SECDSA authentication (Section 4.3)
            RP.AuthResp(C, SigRP);
        }
    }

    private class RelyingParty {

        private final ECPoint G_accent;
        private final byte[] M = "Bletchley Park".getBytes();

        public RelyingParty(ECPoint G_accent) {
            this.G_accent = G_accent;
        }

        public byte[] AuthReq() {
            return M;
        }

        // Figure 9, Step 8
        public void AuthResp(Certificate C, SigRP SigRP) {
            assertThat(splitECDSASignatureValidation(M, C, SigRP), equalTo(true));
        }

        // Algorithm 8 Encrypted SECDSA signature verification by Relying Party
        // Input: message M, User certificate C, SigRP
        // Output: True of False
        private boolean splitECDSASignatureValidation(byte[] M, Certificate C, SigRP SigRP) {
            // 1: Parse SigRP = {SigSF,R′,DT2} on failure return False // inputcheck
            final var SigSF = SigRP.SigSF;
            final var R_accent = SigRP.R_accent;
            final var DT2 = SigRP.DT2;

            // 2: Parse SigSF ={H,(R,S′,S′′),N,DT1} on failure return False
            final var H = SigSF.H;
            final var R = SigSF.R;
            final var S_accent = SigSF.S_accent;
            final var S_double_accent = SigSF.S_double_accent;
            final var N = SigSF.N;
            final var DT1 = SigSF.DT1;

            // 3: Verify certificate C, on failure return False // signed, not revocated
            // 4: Retrieve Y′ from certificate C
            final var Y_accent = C.Y_accent;

            // Verify DT2 on R′ , R, G′ , G, N on failure return False
            assertThat(DTv(R, R_accent, DT2, G_accent, G, N.toByteArray()), equalTo(true));

            // 6: Converts the x-coordinate of R to an integer r ̄; compute r = r ̄ mod q
            final var r = R.getXCoord().toBigInteger().mod(q);

            // 7: Verify H(M) = H on failure return False
            assertThat(H(M), equalTo(H));

            // 8: Convert H to an integer e.
            final var e = new BigInteger(1, H);

            // 9: Verify if R′ = e·S′ + r·S′′ on failure return False
            assertThat(R_accent, equalTo(S_accent.multiply(e).add(S_double_accent.multiply(r))));

            // 10: Verify DT1 on S′, S′′, G′, Y′, N on failure return False
            assertThat(DTv(G_accent, S_accent, DT1, S_double_accent, Y_accent, N.toByteArray()), equalTo(true));

            // 11: Return True
            return true;
        }
    }

    @Test
    public void testProtocols() {

        // Section 3.3 [We also assume that the certificate issuer and
        // signing facilitator have securely agreed a ZKP private key a ∈R F∗q and
        // published the ZKP public key G′ = a·G.]
        final var a = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();
        final var G_accent = G.multiply(a);

        final var CI = new CertificateIssuer(a);
        final var SF = new SigningFacilitator(a);

        // Protocol 1 Certificate issuance to User/S-APP by Certificate Issuer (CI)
        // 1: User chooses PIN, S-APP generates SECDSA key-pair Y using Algorithm 7
        final var u = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        // @todo sigma = PIN-binder(Kp,PIN)
        final var sigma = P_256.getCurve().randomFieldElement(PRNG).toBigInteger();

        final var y = u.multiply(sigma).mod(q);
        final var Y = G.multiply(y);

        // 2: S-APP sends CI identity Id, Y and Proof-of-Possession of y
        final var received = CI.certificateIssuance("N. Nescio", Y);

        // 9: CI sends CId, C, DT, to User
        final var CId = received.CId;
        final var C = received.C;
        final var DT = received.DT;

        // 10: User/S-APP verify C and DT , if successful S-APP stores CId, C
        final var accepted = DTv(Y, C.Y_accent, DT, G_accent, G, new byte[0]);
        assertThat(accepted, equalTo(true));

        // 11: S-APP deletes Y and DT // sensitive data

        // Protocol 2 SECDSA signature generation by S-APP for RP assisted by SF
        // Input: message M
        // Output: SECDSA signature SigRP

        // 1: User opens S-APP and indicates he wants to sign a message.
        final var RP = new RelyingParty(G_accent);
        // [Use case Centralized SECDSA authentication (Section 4.3). Message M is a challenge by RP.]
        final var M = RP.AuthReq();

        // 2: S-APP retrieves CId and certificate C from local storage
        // 3: S-APP sets up session with SF by sending CId and C
        final var N = SF.setupSession(CId, C, RP);

        // 9: S-APP retrieves Y′ from certificate C
        final var Y_accent = C.Y_accent;

        // 10: S-APP requests user to enter PIN
        // 11: S-APP calls SCE to compute σ=P(KP,PIN). // inside SCE
        // @todo sigma = PIN-binder(Kp,PIN)

        // 12: S-APP computes H = H(M) and convert this to an integer e.
        final var H = H(M);
        final var e = new BigInteger(1, H);

        // 13: S-APP computes e′ = σ−1·e mod q
        // 14: S-APP calls SCE to compute raw signature (r,s′) on e′ with SCE-key u // inside SCE
        // 15: S-APP computes s = σ·s′ mod q.
        final var signature = splitECDSASignatureGeneration(e, u, sigma);

        // 16: S-APP transforms (r,s) to full form (R,s) using Proposition 2.1.
        final var R = fullECDSASignatureTransformation(e, signature, Y);
        final var s = signature.s;

        // Section 3.3 [it is well
        // known that one can recover the ECDSA public key used from a valid ECDSA
        // signature on a known message M.]

        // 17: S-APP computes w = s−1 mod q
        final var w = s.modInverse(q);

        // 18: S-APP computes S′ = w·G′ , S′′ = w·Y′ // G′ is ZKP-public key
        // [ S′  relates to G′ in Alg. 3
        //   S′′ relates to U′ in Alg. 3
        //   line 26: Verify if R′ = e·S′ + r·S′′
        //     relates to line 6 in Alg. 3: Compute X = eG′ + rU′.
        //   note presence of factor a in R′, S′ and S′′ (via R′ = a·R, G′ = a·G and Y′ = a.Y)
        //  ]
        final var S_accent = G_accent.multiply(w);
        final var S_double_accent = Y_accent.multiply(w);

        // 19: S-APP Generates ZKP DT1 =DT(G′ →w S′|S′′ =w·Y′,N) // Link ZKP to N
        final var DT1 = DTc(G_accent, w, Y_accent, N.toByteArray());

        // 20: S-APP sends SigSF ={H,(R,S′,S′′),N,DT1} to SF
        // 21: S-APP deletes all transient data
        SF.verify(new SigSF(H, R, S_accent, S_double_accent, N, DT1));
    }
}
