using System;
using System.Linq;

public class BFV
{
    public static int Q = 257;
    public static int T = 17; // plaintext modulus
    public static int N = Rq.N;
    public static int Delta = Q / T; // floor(Q/T)

    public Rq sk;
    public (Rq a, Rq b) pk;
    public (Rq a, Rq b, Rq c) rlk; // relinearization key

    public BFV()
    {
        KeyGen();
    }

    /// <summary>
    /// Generuje klucze: sk, pk, rlk
    /// </summary>
    public void KeyGen()
    {
        sk = SampleBinary();

        var a = SampleUniform();
        var e = SampleError();
        var b = -(a * sk) + e;

        pk = (a, b);

        // Relinearization key: rlk = (a', b', c') = (a1, b1, a1*sk^2 + b1*sk + e')
        var a1 = SampleUniform();
        var b1 = SampleUniform();
        var e1 = SampleError();
        var sk2 = sk * sk;

        var c = a1 * sk2 + b1 * sk + e1;
        rlk = (a1, b1, c);
    }

    /// <summary>
    /// Szyfrowanie m: int[] -> (c0, c1)
    /// </summary>
    public (Rq, Rq) Encrypt(int[] m)
    {
        var mPoly = new Rq(m.Select(x => x * Delta).ToArray());

        var u = SampleBinary();
        var e1 = SampleError();
        var e2 = SampleError();

        var c0 = pk.b * u + e1 + mPoly;
        var c1 = pk.a * u + e2;

        return (c0, c1);
    }

    /// <summary>
    /// Deszyfrowanie (c0, c1) -> m
    /// </summary>
    public int[] Decrypt((Rq, Rq) ct)
    {
        var (c0, c1) = ct;
        var scaled = c0 + (c1 * sk);

        int[] m = new int[N];
        for (int i = 0; i < N; i++)
        {
            int val = (int)Math.Round((double)scaled.coeffs[i] * T / Q);
            m[i] = ((val % T) + T) % T; // Redukcja modulo T, zawsze dodatnia
        }
        return m;
    }

    /// <summary>
    /// Dodawanie szyfrogramów
    /// </summary>
    public (Rq, Rq) EvalAdd((Rq, Rq) ct1, (Rq, Rq) ct2)
    {
        return (ct1.Item1 + ct2.Item1, ct1.Item2 + ct2.Item2);
    }

    /// <summary>
    /// Mnożenie szyfrogramów: (c0, c1) * (d0, d1) = (c0d0, c0d1 + c1d0, c1d1)
    /// </summary>
    public (Rq, Rq) EvalMult((Rq, Rq) ct1, (Rq, Rq) ct2)
    {
        var (c0, c1) = ct1;
        var (d0, d1) = ct2;

        var t0 = c0 * d0;
        var t1 = c0 * d1 + c1 * d0;
        var t2 = c1 * d1;

        // Poprawna relinearizacja FV: (t0, t1, t2) → (t0 + rlk.c, t1)
        var newC0 = t0 + rlk.c;
        var newC1 = t1;
        return (newC0, newC1);
    }

    /// <summary>
    /// Próbkowanie z rozkładu binarnego: {0, 1}^N
    /// </summary>
    private Rq SampleBinary()
    {
        var rnd = new Random();
        int[] coeffs = new int[N];
        for (int i = 0; i < N; i++)
        {
            coeffs[i] = rnd.Next(2); // 0 lub 1
        }
        return new Rq(coeffs);
    }

    /// <summary>
    /// Jednorodna losowość z [0, Q)
    /// </summary>
    private Rq SampleUniform()
    {
        var rnd = new Random();
        int[] coeffs = new int[N];
        for (int i = 0; i < N; i++)
        {
            coeffs[i] = rnd.Next(Q);
        }
        return new Rq(coeffs);
    }

    /// <summary>
    /// Próbkowanie szumu z małego rozkładu (np. {-1, 0, 1})
    /// </summary>
    private Rq SampleError()
    {
        var rnd = new Random();
        int[] coeffs = new int[N];
        for (int i = 0; i < N; i++)
        {
            coeffs[i] = rnd.Next(-1, 2); // -1, 0, 1
        }
        return new Rq(coeffs);
    }
}
