using System;
using System.Numerics;

public class Poly
{
    public int N;
    public BigInteger Q;
    public List<BigInteger[]> NTTParams;
    public List<BigInteger> F;
    public bool InNTT;

    public Poly(int n, BigInteger q, List<BigInteger[]> np)
    {
        N = n;
        Q = q;
        NTTParams = np;
        F = new List<BigInteger>(new BigInteger[n]);
        InNTT = false;
    }

    public void Randomize(int B, bool domain = false, int type = 0, double mu = 0, double sigma = 0)
    {
        if (type == 0)
        {
            var rnd = new Random();
            for (int i = 0; i < N; i++)
            {
                int val = rnd.Next(-B / 2, B / 2);
                F[i] = ((val % Q) + Q) % Q;
            }
            InNTT = domain;
        }
        else
        {
            var rng = new Random();
            for (int i = 0; i < N; i++)
            {
                // Box-Muller transform
                double u1 = 1.0 - rng.NextDouble();
                double u2 = 1.0 - rng.NextDouble();
                double randStdNormal = Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Sin(2.0 * Math.PI * u2);
                double val = mu + sigma * randStdNormal;
                F[i] = ((BigInteger)((int)Math.Round(val)) % Q + Q) % Q;
            }
            InNTT = domain;
        }
    }
    public override string ToString()
    {
        string pstr = F[0].ToString();
        int tmp = Math.Min(N, 8);

        for (int i = 1; i < tmp; i++)
        {
            pstr += $" + {F[i]}*x^{i}";
        }

        if (N > 8)
        {
            pstr += " + ...";
        }

        return pstr;
    }

    public static Poly operator +(Poly a, Poly b)
    {
        if (a.InNTT != b.InNTT)
            throw new Exception("Polynomial Addition: Inputs must be in the same domain.");
        if (a.Q != b.Q)
            throw new Exception("Polynomial Addition: Inputs must have the same modulus.");

        Poly c = new Poly(a.N, a.Q, a.NTTParams);
        for (int i = 0; i < a.N; i++)
        {
            c.F[i] = (a.F[i] + b.F[i]) % a.Q;
            if (c.F[i] < 0) c.F[i] += a.Q;
        }
        c.InNTT = a.InNTT;
        return c;
    }
    
    public static Poly operator -(Poly a, Poly b)
    {
        if (a.InNTT != b.InNTT)
            throw new Exception("Polynomial Subtraction: Inputs must be in the same domain.");
        if (a.Q != b.Q)
            throw new Exception("Polynomial Subtraction: Inputs must have the same modulus.");

        Poly c = new Poly(a.N, a.Q, a.NTTParams);
        for (int i = 0; i < a.N; i++)
        {
            c.F[i] = (a.F[i] - b.F[i]) % a.Q;
            if (c.F[i] < 0) c.F[i] += a.Q;
        }
        c.InNTT = a.InNTT;
        return c;
    }
    
    public static Poly operator *(Poly a, Poly b)
    {
        if (a.InNTT != b.InNTT)
            throw new Exception("Polynomial Multiplication: Inputs must be in the same domain.");
        if (a.Q != b.Q)
            throw new Exception("Polynomial Multiplication: Inputs must have the same modulus.");

        Poly c = new Poly(a.N, a.Q, a.NTTParams);

        if (a.InNTT && b.InNTT)
        {
            for (int i = 0; i < a.N; i++)
            {
                c.F[i] = (a.F[i] * b.F[i]) % a.Q;
                if (c.F[i] < 0) c.F[i] += a.Q;
            }
            c.InNTT = true;
        }
        else
        {
            var wTable = a.NTTParams[0];
            var wvTable = a.NTTParams[1];
            var psiTable = a.NTTParams[2];
            var psivTable = a.NTTParams[3];

            BigInteger[] s_p = new BigInteger[a.N];
            BigInteger[] b_p = new BigInteger[a.N];

            for (int i = 0; i < a.N; i++)
            {
                s_p[i] = a.F[i] * psiTable[i] % a.Q;
                if (s_p[i] < 0) s_p[i] += a.Q;
                b_p[i] = b.F[i] * psiTable[i] % a.Q;
                if (b_p[i] < 0) b_p[i] += a.Q;
            }

            var s_n = NTT.Transform(s_p, wTable, a.Q);
            var b_n = NTT.Transform(b_p, wTable, a.Q);

            BigInteger[] sb_n = new BigInteger[a.N];
            for (int i = 0; i < a.N; i++)
            {
                sb_n[i] = (s_n[i] * b_n[i]) % a.Q;
                if (sb_n[i] < 0) sb_n[i] += a.Q;
            }

            var sb_p = NTT.INTT(sb_n, wvTable, a.Q);

            for (int i = 0; i < a.N; i++)
            {
                c.F[i] = (sb_p[i] * psivTable[i]) % a.Q;
                if (c.F[i] < 0) c.F[i] += a.Q;
            }

            c.InNTT = false;
        }

        return c;
    }




}
