using System;
using System.Linq;


public class BFV
{
    public static int t = 8;   // Modulo plaintextu
    public static int q = Rq.q; // Modulo ciphertextu

    public Rq sk;   // Secret key
    public (Rq, Rq) pk; // Public key (pk0, pk1)
    public (Rq, Rq)[] rlkTab; // Relinearization key: tablica par (rlk0[j], rlk1[j]) dla każdego bitu/cyfry (pełna relinearyzacja BFV)

    // Noise budget: max log2(q/t) - log2(noise)
    public int maxNoiseBudget = (int)Math.Floor(Math.Log(q / (double)t, 2));

    Random rand = new Random();

    public BFV()
    {
        KeyGen();
    }

    private int[] SampleTernary(int n)
    {
        // R2: tylko 0/1
        return Enumerable.Range(0, n).Select(_ => rand.Next(2)).ToArray();
    }


    private Rq SampleError()
    {
        return new Rq(SampleTernary(Rq.N));
    }


    private Rq RandomPoly()
    {
        int[] coeffs = Enumerable.Range(0, Rq.N).Select(_ => rand.Next(q)).ToArray();
        return new Rq(coeffs);
    }

    public void KeyGen()
    {
        sk = new Rq(SampleTernary(Rq.N)); 
        var a = RandomPoly();
        var e = SampleError();
        var pk0 = -(a * sk + t * e);
        var pk1 = a;
        pk = (pk0, pk1);

        int logq = (int)Math.Ceiling(Math.Log(q, 2));
        rlkTab = new (Rq, Rq)[logq];
        for (int j = 0; j < logq; j++)
        {
            var a_rlk = RandomPoly();
            var e_rlk = SampleError();
            // rlk0 = a_rlk * sk + t * e_rlk + 2^j * sk * sk
            var rlk0 = a_rlk * sk + t * e_rlk + (1 << j) * sk * sk;
            var rlk1 = -a_rlk;
            rlkTab[j] = (rlk0, rlk1);
        }
    }

    // Ciphertext: (Rq, Rq, int noise)
    public (Rq, Rq, int) Encrypt(Rq m)
    {
        var (pk0, pk1) = pk;

        // Skalowanie wiadomości przez Δ = floor(q / t)
        int delta = q / t;
        Rq mScaled = new Rq(m.Coeffs.Select(x => (x * delta) % q).ToArray());

        // u z R_2 (losowe 0/1)
        int[] uArr = Enumerable.Range(0, Rq.N).Select(_ => rand.Next(2)).ToArray();
        Rq u = new Rq(uArr);
        Rq e0 = SampleError();
        Rq e1 = SampleError();

        Rq c0 = pk0 * u + t * e0 + mScaled;
        Rq c1 = pk1 * u + t * e1;

        int noise = MaxAbsCoeff(t * e0 + mScaled);
        return (c0, c1, noise);
    }

    public Rq Decrypt((Rq, Rq, int) ct)
    {
        var (c0, c1, _) = ct;
        Rq result = c0 + (c1 * sk);
        // Odskalowanie przez delta i zaokrąglenie
        int delta = q / t;
        int[] coeffs = result.Coeffs.Select(x => {
            int v = ((x % q) + q) % q;
            int rounded = (int)Math.Round(v / (double)delta);
            return ((rounded % t) + t) % t;
        }).ToArray();
        return new Rq(coeffs);
    }

    public (Rq, Rq, int) Add((Rq, Rq, int) ct1, (Rq, Rq, int) ct2)
    {
        // Dodajemy ciphertexty i sumujemy szumy
        var c0 = ct1.Item1 + ct2.Item1;
        var c1 = ct1.Item2 + ct2.Item2;
        int noise = ct1.Item3 + ct2.Item3;
        return (c0, c1, noise);
    }

    public (Rq, Rq, int) Mul((Rq, Rq, int) ct1, (Rq, Rq, int) ct2)
    {
        var (c0a, c1a, noise1) = ct1;
        var (c0b, c1b, noise2) = ct2;

        Rq c0 = c0a * c0b;
        Rq c1 = c0a * c1b + c1a * c0b;
        Rq c2 = c1a * c1b;

        // Relinearyzacja: dekompozycja c2 na bity i użycie rlkTab
        int logq = (int)Math.Ceiling(Math.Log(q, 2));
        int[][] c2bits = BitDecomp(c2, logq); // [N][logq]
        Rq sum0 = new Rq(new int[Rq.N]);
        Rq sum1 = new Rq(new int[Rq.N]);
        for (int j = 0; j < logq; j++)
        {
            int[] bitj = new int[Rq.N];
            for (int i = 0; i < Rq.N; i++) bitj[i] = c2bits[i][j];
            var bitPoly = new Rq(bitj);
            var (rlk0, rlk1) = rlkTab[j];
            sum0 = sum0 + (rlk0 * bitPoly);
            sum1 = sum1 + (rlk1 * bitPoly);
        }
        Rq c0p = c0 + sum0;
        Rq c1p = c1 + sum1;

        int noise = noise1 * noise2;
        return (c0p, c1p, noise);
    }

    // Modulus switching: zmniejsz q i szum
    public (Rq, Rq, int) ModSwitch((Rq, Rq, int) ct, int newQ)
    {
        var c0 = ct.Item1 % newQ;
        var c1 = ct.Item2 % newQ;
        int noise = (int)Math.Floor(ct.Item3 * (newQ / (double)q));
        return (c0, c1, noise);
    }

    // Odczytaj noise budget (ile bitów szumu pozostało)
    public int GetNoiseBudget((Rq, Rq, int) ct)
    {
        if (ct.Item3 == 0) return maxNoiseBudget;
        return maxNoiseBudget - (int)Math.Ceiling(Math.Log(ct.Item3, 2));
    }

    // Pomocnicza: max wartość bezwzględna współczynnika
    private int MaxAbsCoeff(Rq poly)
    {
        return poly.Coeffs.Select(Math.Abs).Max();
    }

    // BitDecomp: rozkłada każdy współczynnik na bity (little-endian)
    private int[][] BitDecomp(Rq poly, int logq)
    {
        int[][] bits = new int[Rq.N][];
        for (int i = 0; i < Rq.N; i++)
        {
            bits[i] = new int[logq];
            int v = poly.Coeffs[i];
            for (int j = 0; j < logq; j++)
            {
                bits[i][j] = v & 1;
                v >>= 1;
            }
        }
        return bits;
    }

    // PowersOf2: zwraca [sk, 2*sk, 4*sk, ...] do logq
    private Rq[] PowersOf2(Rq sk, int logq)
    {
        Rq[] res = new Rq[logq];
        Rq pow = sk;
        for (int i = 0; i < logq; i++)
        {
            res[i] = pow;
            pow = 2 * pow;
        }
        return res;
    }
}
