using System;
using System.Collections.Generic;
using System.Numerics;

public class BFV
{
    // Parameters
    public int n; // ring size
    public BigInteger q; // ciphertext modulus
    public BigInteger t; // plaintext modulus
    public double mu; // distribution mean
    public double sigma; // distribution std. dev.
    public List<BigInteger[]> qnp; // NTT parameters: [w, w_inv, psi, psi_inv]

    // Other parameters
    public BigInteger T = 0;
    public int l = 0;
    public BigInteger p = 0;

    // Keys
    public Poly? sk = null;
    public List<Poly> pk = new List<Poly>();
    public List<List<Poly>> rlk1 = new List<List<Poly>>();
    public List<Poly> rlk2 = new List<Poly>();

    // Constructor
    public BFV(int n, BigInteger q, BigInteger t, double mu, double sigma, List<BigInteger[]> qnp)
    {
        this.n = n;
        this.q = q;
        this.t = t;
        this.mu = mu;
        this.sigma = sigma;
        this.qnp = qnp;
        // T, l, p are left as default (0)
    }

    public override string ToString()
    {
        string str = "\n--- Parameters:\n";
        str += $"n    : {n}\n";
        str += $"q    : {q}\n";
        str += $"t    : {t}\n";
        str += $"T    : {T}\n";
        str += $"l    : {l}\n";
        str += $"p    : {p}\n";
        str += $"mu   : {mu}\n";
        str += $"sigma: {sigma}\n";
        return str;
    }
    public void SecretKeyGen()
    {
        // sk <- R_2
        var s = new Poly(n, q, qnp);
        s.Randomize(2); // Randomize over {0,1}
        this.sk = s;
    }
    public void PublicKeyGen()
    {
        // a <- R_q
        // e <- X
        // pk[0] <- (-(a*sk)+e) mod q
        // pk[1] <- a

        var a = new Poly(n, q, qnp);
        var e = new Poly(n, q, qnp);

        a.Randomize(q); // Uniform random in R_q
        e.Randomize(0, domain: false, type: 1, mu: mu, sigma: sigma); // Gaussian noise

        var pk0 = -(a * sk + e);
        var pk1 = a;

        this.pk = new List<Poly> { pk0, pk1 };
    }

    public void EvalKeyGenV1(BigInteger T)
    {
        this.T = T;
        this.l = (int)Math.Floor(BigInteger.Log(q, (double)T));

        var rlk1 = new List<List<Poly>>();

        Poly sk2 = sk * sk;

        for (int i = 0; i <= l; i++)
        {
            var ai = new Poly(n, q, qnp);
            var ei = new Poly(n, q, qnp);
            ai.Randomize(q);
            ei.Randomize(0, domain: false, type: 1, mu: mu, sigma: sigma);

            var Ts2 = new Poly(n, q, qnp);
            for (int j = 0; j < n; j++)
            {
                Ts2.F[j] = (BigInteger.Pow(T, i) * sk2.F[j]) % q;
            }

            var rlki0 = Ts2 - (ai * sk + ei);
            var rlki1 = ai;

            rlk1.Add(new List<Poly> { rlki0, rlki1 });
        }

        this.rlk1 = rlk1;
    }

    public void EvalKeyGenV2(BigInteger p)
    {
        /*
        a <- R_{p*q}
        e <- X'
        rlk[0] = [-(a*sk+e)+p*s^2]_{p*q}
        rlk[1] =  a
        */
        this.p = p;

        var rlk2 = new List<Poly>();

        BigInteger pq = p * q;

        var a = new Poly(n, pq, qnp);
        var e = new Poly(n, pq, qnp);

        a.Randomize(pq);
        e.Randomize(0, domain: false, type: 1, mu: mu, sigma: sigma);

        // c0 = a*sk + e
        var c0 = Helper.RefPolMulv2(a.F, sk.F);
        for (int i = 0; i < n; i++)
            c0[i] = (c0[i] + e.F[i]) % pq;

        // c1 = p * (sk*sk)
        var sk2 = Helper.RefPolMulv2(sk.F, sk.F);
        for (int i = 0; i < n; i++)
            sk2[i] = (p * sk2[i]) % pq;

        // c2 = (c1 - c0) mod pq
        var c2 = new List<BigInteger>(n);
        for (int i = 0; i < n; i++)
            c2.Add((sk2[i] - c0[i] + pq) % pq);

        var c = new Poly(n, pq, qnp);
        c.F = c2;

        rlk2.Add(c);
        rlk2.Add(a);

        this.rlk2 = rlk2;
    }

    public List<Poly> Encryption(Poly m)
    {
        /*
        delta = floor(q/t)

        u  <- random polynomial from R_2
        e1 <- random polynomial from R_B
        e2 <- random polynomial from R_B

        c0 <- pk0*u + e1 + m*delta
        c1 <- pk1*u + e2
        */
        BigInteger delta = BigInteger.Divide(q, t);

        var u = new Poly(n, q, qnp);
        var e1 = new Poly(n, q, qnp);
        var e2 = new Poly(n, q, qnp);

        u.Randomize(2);
        e1.Randomize(0, domain: false, type: 1, mu: mu, sigma: sigma);
        e2.Randomize(0, domain: false, type: 1, mu: mu, sigma: sigma);

        var md = new Poly(n, q, qnp);
        for (int i = 0; i < n; i++)
            md.F[i] = (delta * m.F[i]) % q;

        var c0 = pk[0] * u + e1 + md;
        var c1 = pk[1] * u + e2;

        return new List<Poly> { c0, c1 };
    }
    public Poly Decryption(List<Poly> ct)
    {
        /*
        ct <- c1*s + c0
        ct <- floor(ct*(t/q))
        m <- [ct]_t
        */
        // c1 * sk + c0
        Poly m = ct[1] * sk + ct[0];

        // Scale and round each coefficient
        for (int i = 0; i < n; i++)
        {
            // (t * x) / q, rounded to nearest integer
            m.F[i] = BigInteger.Divide((t * m.F[i] + q / 2), q); // rounding
            m.F[i] = ((m.F[i] % t) + t) % t; // mod t, always positive
        }

        Poly mr = new Poly(n, t, qnp);
        for (int i = 0; i < n; i++)
            mr.F[i] = m.F[i];
        mr.InNTT = m.InNTT;

        return mr;
    }

    public Poly DecryptionV2(List<Poly> ct)
    {
        /*
        ct <- c2*s^2 + c1*s + c0
        ct <- floor(ct*(t/q))
        m <- [ct]_t
        */
        Poly sk2 = sk * sk;

        Poly m = ct[0] + (ct[1] * sk) + (ct[2] * sk2);

        // Scale and round each coefficient
        for (int i = 0; i < n; i++)
        {
            // (t * x) / q, rounded to nearest integer
            m.F[i] = BigInteger.Divide((t * m.F[i] + q / 2), q); // rounding
            m.F[i] = ((m.F[i] % t) + t) % t; // mod t, always positive
        }

        Poly mr = new Poly(n, t, qnp);
        for (int i = 0; i < n; i++)
            mr.F[i] = m.F[i];
        mr.InNTT = m.InNTT;

        return mr;
    }

    public List<Poly> RelinearizationV1(List<Poly> ct)
    {
        Poly c0 = ct[0];
        Poly c1 = ct[1];
        Poly c2 = ct[2];

        // Divide c2 into base T
        var c2i = new List<Poly>();

        Poly c2q = new Poly(n, q, qnp);
        for (int j = 0; j < n; j++)
            c2q.F[j] = c2.F[j];

        for (int i = 0; i <= l; i++)
        {
            Poly c2r = new Poly(n, q, qnp);

            for (int j = 0; j < n; j++)
            {
                BigInteger qt = c2q.F[j] / T;
                BigInteger rt = c2q.F[j] - qt * T;

                c2q.F[j] = qt;
                c2r.F[j] = rt;
            }

            c2i.Add(c2r);
        }

        Poly c0r = new Poly(n, q, qnp);
        Poly c1r = new Poly(n, q, qnp);
        for (int j = 0; j < n; j++)
        {
            c0r.F[j] = c0.F[j];
            c1r.F[j] = c1.F[j];
        }

        for (int i = 0; i <= l; i++)
        {
            c0r = c0r + (rlk1[i][0] * c2i[i]);
            c1r = c1r + (rlk1[i][1] * c2i[i]);
        }

        return new List<Poly> { c0r, c1r };
    }

    public List<Poly> RelinearizationV2(List<Poly> ct)
    {
        Poly c0 = ct[0];
        Poly c1 = ct[1];
        Poly c2 = ct[2];

        // Multiply and scale c2 with rlk2[0]
        var c2_0 = Helper.RefPolMulv2(c2.F, rlk2[0].F);
        for (int i = 0; i < n; i++)
        {
            c2_0[i] = BigInteger.Divide(c2_0[i] + p / 2, p); // rounding
            c2_0[i] = ((c2_0[i] % q) + q) % q; // mod q, always positive
        }

        // Multiply and scale c2 with rlk2[1]
        var c2_1 = Helper.RefPolMulv2(c2.F, rlk2[1].F);
        for (int i = 0; i < n; i++)
        {
            c2_1[i] = BigInteger.Divide(c2_1[i] + p / 2, p); // rounding
            c2_1[i] = ((c2_1[i] % q) + q) % q; // mod q, always positive
        }

        Poly c0e = new Poly(n, q, qnp); c0e.F = c2_0;
        Poly c1e = new Poly(n, q, qnp); c1e.F = c2_1;

        Poly c0r = c0e + c0;
        Poly c1r = c1e + c1;

        return new List<Poly> { c0r, c1r };
    }

    public Poly IntEncode(BigInteger m)
    {
        Poly mr = new Poly(n, t, qnp);

        if (m > 0)
        {
            BigInteger mt = m;
            for (int i = 0; i < n; i++)
            {
                mr.F[i] = mt % 2;
                mt = mt / 2;
            }
        }
        else if (m < 0)
        {
            BigInteger mt = -m;
            for (int i = 0; i < n; i++)
            {
                mr.F[i] = (t - (mt % 2)) % t;
                mt = mt / 2;
            }
        }
        return mr;
    }
    public BigInteger IntDecode(Poly m)
    {
        BigInteger mr = 0;
        BigInteger thr_ = (t == 2) ? 2 : ((t + 1) >> 1);

        for (int i = 0; i < n; i++)
        {
            BigInteger c = m.F[i];
            BigInteger c_;
            if (c >= thr_)
                c_ = -(t - c);
            else
                c_ = c;
            mr += c_ * BigInteger.Pow(2, i);
        }
        return mr;
    }
    public List<Poly> HomomorphicAddition(List<Poly> ct0, List<Poly> ct1)
    {
        Poly ct0_b = ct0[0] + ct1[0];
        Poly ct1_b = ct0[1] + ct1[1];
        return new List<Poly> { ct0_b, ct1_b };
    }
    public List<Poly> HomomorphicSubtraction(List<Poly> ct0, List<Poly> ct1)
    {
        Poly ct0_b = ct0[0] - ct1[0];
        Poly ct1_b = ct0[1] - ct1[1];
        return new List<Poly> { ct0_b, ct1_b };
    }
    
    public List<Poly> HomomorphicMultiplication(List<Poly> ct0, List<Poly> ct1)
    {
        Poly ct00 = ct0[0];
        Poly ct01 = ct0[1];
        Poly ct10 = ct1[0];
        Poly ct11 = ct1[1];

        var r0 = Helper.RefPolMulv2(ct00.F, ct10.F);
        var r1 = Helper.RefPolMulv2(ct00.F, ct11.F);
        var r2 = Helper.RefPolMulv2(ct01.F, ct10.F);
        var r3 = Helper.RefPolMulv2(ct01.F, ct11.F);

        var c0 = new List<BigInteger>(n);
        var c1 = new List<BigInteger>(n);
        var c2 = new List<BigInteger>(n);

        for (int i = 0; i < n; i++)
        {
            // c0 = r0
            BigInteger val0 = (t * r0[i]) / q;
            val0 = ((BigInteger)Math.Round((double)val0) % q + q) % q;
            c0.Add(val0);

            // c1 = r1 + r2
            BigInteger val1 = (t * (r1[i] + r2[i])) / q;
            val1 = ((BigInteger)Math.Round((double)val1) % q + q) % q;
            c1.Add(val1);

            // c2 = r3
            BigInteger val2 = (t * r3[i]) / q;
            val2 = ((BigInteger)Math.Round((double)val2) % q + q) % q;
            c2.Add(val2);
        }

        Poly r0_poly = new Poly(n, q, qnp) { F = c0 };
        Poly r1_poly = new Poly(n, q, qnp) { F = c1 };
        Poly r2_poly = new Poly(n, q, qnp) { F = c2 };

        return new List<Poly> { r0_poly, r1_poly, r2_poly };
    }
}

    