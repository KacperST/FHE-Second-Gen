using System;
using System.Numerics;
using System.Collections.Generic;

class Program
{
    static void Maain(string[] args)
    {
        var (n, q, t, psi, psiv, w, wv, qnp, mu, sigma, T, p) = SetupParameters();

        var Evaluator = new BFV(n, q, t, mu, sigma, qnp);
        GenerateKeys(Evaluator, T, p);

        int n1, n2;
        GenerateRandomMessages(out n1, out n2);

        Poly m1, m2;
        List<Poly> ct1, ct2;
        EncodeAndEncrypt(Evaluator, n1, n2, out m1, out m2, out ct1, out ct2);

        HomomorphicAdditionDemo(Evaluator, ct1, ct2, n1, n2);

        HomomorphicSubtractionDemo(Evaluator, ct1, ct2, n1, n2);

        HomomorphicMultiplicationDemo(Evaluator, ct1, ct2, n1, n2);

        HomomorphicMultiplicationRelinV1Demo(Evaluator, ct1, ct2, n1, n2);

        HomomorphicMultiplicationRelinV2Demo(Evaluator, ct1, ct2, n1, n2);
    }

    static (int n, BigInteger q, BigInteger t, BigInteger psi, BigInteger psiv, BigInteger w, BigInteger wv, List<BigInteger[]> qnp, double mu, double sigma, int T, BigInteger p) SetupParameters()
    {
        var PD = 0;
        BigInteger t, q, psi, psiv, w, wv;
        int n, logq;

        if (PD == 0)
        {
            t = 16;
            n = 1024;
            q = 132120577;
            psi = 73993;
            psiv = Helper.ModInv(psi, q);
            w = BigInteger.ModPow(psi, 2, q);
            wv = Helper.ModInv(w, q);
        }
        else
        {
            t = 16; n = 1024; logq = 27;
            (q, psi, psiv, w, wv) = Helper.ParamGen(n, logq);
        }

        var mu = 0.0;
        var sigma = 0.5 * 3.2;
        var T = 256;
        var p = BigInteger.Pow(q, 3) + 1;

        BigInteger[] w_table = new BigInteger[n];
        BigInteger[] wv_table = new BigInteger[n];
        BigInteger[] psi_table = new BigInteger[n];
        BigInteger[] psiv_table = new BigInteger[n];

        w_table[0] = 1;
        wv_table[0] = 1;
        psi_table[0] = 1;
        psiv_table[0] = 1;

        for (int i = 1; i < n; i++)
        {
            w_table[i] = (w_table[i - 1] * w) % q;
            wv_table[i] = (wv_table[i - 1] * wv) % q;
            psi_table[i] = (psi_table[i - 1] * psi) % q;
            psiv_table[i] = (psiv_table[i - 1] * psiv) % q;
        }

        var qnp = new List<BigInteger[]>
        {
            w_table,
            wv_table,
            psi_table,
            psiv_table
        };

        Console.WriteLine("--- Starting BFV Demo");
        return (n, q, t, psi, psiv, w, wv, qnp, mu, sigma, T, p);
    }

    static void GenerateKeys(BFV Evaluator, int T, BigInteger p)
    {
        Evaluator.SecretKeyGen();
        Evaluator.PublicKeyGen();
        Evaluator.EvalKeyGenV1(T);
        Evaluator.EvalKeyGenV2(p);
        Console.WriteLine(Evaluator);
    }

    static void GenerateRandomMessages(out int n1, out int n2)
    {
        Random rnd = new Random();
        n1 = rnd.Next(-(1 << 15), (1 << 15));
        n2 = rnd.Next(-(1 << 15), (1 << 15) - 1);

        Console.WriteLine("--- Random integers n1 and n2 are generated.");
        Console.WriteLine($"* n1: {n1}");
        Console.WriteLine($"* n2: {n2}");
        Console.WriteLine($"* n1+n2: {n1 + n2}");
        Console.WriteLine($"* n1-n2: {n1 - n2}");
        Console.WriteLine($"* n1*n2: {n1 * n2}");
        Console.WriteLine();
    }

    static void EncodeAndEncrypt(BFV Evaluator, int n1, int n2, out Poly m1, out Poly m2, out List<Poly> ct1, out List<Poly> ct2)
    {
        Console.WriteLine("--- n1 and n2 are encoded as polynomials m1(x) and m2(x).");
        m1 = Evaluator.IntEncode(n1);
        m2 = Evaluator.IntEncode(n2);

        Console.WriteLine($"* m1(x): {m1}");
        Console.WriteLine($"* m2(x): {m2}");
        Console.WriteLine();

        ct1 = Evaluator.Encryption(m1);
        ct2 = Evaluator.Encryption(m2);

        Console.WriteLine("--- m1 and m2 are encrypted as ct1 and ct2.");
        Console.WriteLine($"* ct1[0]: {ct1[0]}");
        Console.WriteLine($"* ct1[1]: {ct1[1]}");
        Console.WriteLine($"* ct2[0]: {ct2[0]}");
        Console.WriteLine($"* ct2[1]: {ct2[1]}");
        Console.WriteLine();
    }

    static void HomomorphicAdditionDemo(BFV Evaluator, List<Poly> ct1, List<Poly> ct2, int n1, int n2)
    {
        var ct = Evaluator.HomomorphicAddition(ct1, ct2);
        var mt = Evaluator.Decryption(ct);

        BigInteger nr = Evaluator.IntDecode(mt);
        BigInteger ne = n1 + n2;

        Console.WriteLine("--- Performing ct_add = Enc(m1) + Enc(m2)");
        Console.WriteLine($"* ct_add[0] :{ct[0]}");
        Console.WriteLine($"* ct_add[1] :{ct[1]}");
        Console.WriteLine("--- Performing ct_dec = Dec(ct_add)");
        Console.WriteLine($"* ct_dec    :{mt}");
        Console.WriteLine("--- Performing ct_dcd = Decode(ct_dec)");
        Console.WriteLine($"* ct_dcd    :{nr}");

        if (nr == ne)
            Console.WriteLine("* Homomorphic addition works.");
        else
            Console.WriteLine("* Homomorphic addition does not work.");
        Console.WriteLine();
    }

    static void HomomorphicSubtractionDemo(BFV Evaluator, List<Poly> ct1, List<Poly> ct2, int n1, int n2)
    {
        var ct_sub = Evaluator.HomomorphicSubtraction(ct1, ct2);
        var mt_sub = Evaluator.Decryption(ct_sub);

        BigInteger nr_sub = Evaluator.IntDecode(mt_sub);
        BigInteger ne_sub = n1 - n2;

        Console.WriteLine("--- Performing ct_sub = Enc(m1) - Enc(m2)");
        Console.WriteLine($"* ct_sub[0] :{ct_sub[0]}");
        Console.WriteLine($"* ct_sub[1] :{ct_sub[1]}");
        Console.WriteLine("--- Performing ct_dec = Dec(ct_sub)");
        Console.WriteLine($"* ct_dec    :{mt_sub}");
        Console.WriteLine("--- Performing ct_dcd = Decode(ct_dec)");
        Console.WriteLine($"* ct_dcd    :{nr_sub}");

        if (nr_sub == ne_sub)
            Console.WriteLine("* Homomorphic subtraction works.");
        else
            Console.WriteLine("* Homomorphic subtraction does not work.");
        Console.WriteLine();
    }

    static void HomomorphicMultiplicationDemo(BFV Evaluator, List<Poly> ct1, List<Poly> ct2, int n1, int n2)
    {
        var ct = Evaluator.HomomorphicMultiplication(ct1, ct2);
        var mt = Evaluator.DecryptionV2(ct);

        BigInteger nr = Evaluator.IntDecode(mt);
        BigInteger ne = (BigInteger)n1 * n2;

        Console.WriteLine("--- Performing ct_mul = Enc(m1) * Enc(m2) (no relinearization)");
        Console.WriteLine($"* ct_mul[0] :{ct[0]}");
        Console.WriteLine($"* ct_mul[1] :{ct[1]}");
        Console.WriteLine("--- Performing ct_dec = Dec(ct_sub)");
        Console.WriteLine($"* ct_dec    :{mt}");
        Console.WriteLine("--- Performing ct_dcd = Decode(ct_dec)");
        Console.WriteLine($"* ct_dcd    :{nr}");

        if (nr == ne)
            Console.WriteLine("* Homomorphic multiplication works.");
        else
            Console.WriteLine("* Homomorphic multiplication does not work.");
        Console.WriteLine($"* Actual: {nr}");
        Console.WriteLine($"* Expected: {ne}");
        Console.WriteLine($"* Difference: {nr - ne}");
        Console.WriteLine();
    }

    static void HomomorphicMultiplicationRelinV1Demo(BFV Evaluator, List<Poly> ct1, List<Poly> ct2, int n1, int n2)
    {
        var ct_ = Evaluator.HomomorphicMultiplication(ct1, ct2);
        var ct = Evaluator.RelinearizationV1(ct_);
        var mt = Evaluator.Decryption(ct);

        BigInteger nr = Evaluator.IntDecode(mt);
        BigInteger ne = (BigInteger)n1 * n2;

        Console.WriteLine("--- Performing ct_mul = Enc(m1) * Enc(m2) (with relinearization v1)");
        Console.WriteLine($"* ct_mul[0] :{ct[0]}");
        Console.WriteLine($"* ct_mul[1] :{ct[1]}");
        Console.WriteLine("--- Performing ct_dec = Dec(ct_sub)");
        Console.WriteLine($"* ct_dec    :{mt}");
        Console.WriteLine("--- Performing ct_dcd = Decode(ct_dec)");
        Console.WriteLine($"* ct_dcd    :{nr}");

        if (nr == ne)
            Console.WriteLine("* Homomorphic multiplication works.");
        else
            Console.WriteLine("* Homomorphic multiplication does not work.");
        Console.WriteLine();
    }

    static void HomomorphicMultiplicationRelinV2Demo(BFV Evaluator, List<Poly> ct1, List<Poly> ct2, int n1, int n2)
    {
        var ct_mul_v2 = Evaluator.HomomorphicMultiplication(ct1, ct2);
        ct_mul_v2 = Evaluator.RelinearizationV2(ct_mul_v2);
        var mt_mul_v2 = Evaluator.Decryption(ct_mul_v2);

        BigInteger nr_mul_v2 = Evaluator.IntDecode(mt_mul_v2);
        BigInteger ne_mul_v2 = n1 * n2;

        Console.WriteLine("--- Performing ct_mul = Enc(m1) * Enc(m2) (with relinearization v2)");
        Console.WriteLine($"* ct_mul[0] :{ct_mul_v2[0]}");
        Console.WriteLine($"* ct_mul[1] :{ct_mul_v2[1]}");
        Console.WriteLine("--- Performing ct_dec = Dec(ct_sub)");
        Console.WriteLine($"* ct_dec    :{mt_mul_v2}");
        Console.WriteLine("--- Performing ct_dcd = Decode(ct_dec)");
        Console.WriteLine($"* ct_dcd    :{nr_mul_v2}");

        if (nr_mul_v2 == ne_mul_v2)
            Console.WriteLine("* Homomorphic multiplication works.");
        else
            Console.WriteLine("* Homomorphic multiplication does not work.");
            Console.WriteLine($"Actual: {nr_mul_v2}");
        Console.WriteLine($"* Expected: {ne_mul_v2}");
        Console.WriteLine($"* Difference: {nr_mul_v2 - ne_mul_v2}");

        Console.WriteLine();
    }
}