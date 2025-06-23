using System;
using System.Numerics;
using System.Collections.Generic;
using System.Diagnostics;

class Benchmark
{
    static Dictionary<int, BigInteger[]> NQ_map = new Dictionary<int, BigInteger[]>
    {
        { 1024, new BigInteger[] { 1714177, 33533953, 132120577 } },
        { 2048, new BigInteger[] { 3428353, 67067905, 264241153 } },
        { 4096, new BigInteger[] { 6856705, 134135809, 528482305 } }
    };
    static int t = 16;
    static int maxCoeff = 10;   
    static double sigma = 3.2;
    static double mu = 0.0;
    static int T = 256;

    public static void Main(string[] args)
    {
        foreach (var kv in NQ_map)
        {
            int n = kv.Key;
            foreach (var q in kv.Value)
            {
                Console.WriteLine($"\n--- Benchmark: N={n}, Q={q}");
                RunBenchmark(n, q);
            }
        }
    }

    static void RunBenchmark(int n, BigInteger q)
    {
        // Setup NTT params (dummy, for compatibility)
        BigInteger psi = 3; // Just a placeholder, not used in this benchmark
        BigInteger psiv = 1;
        BigInteger w = 1;
        BigInteger wv = 1;
        var qnp = new List<BigInteger[]>();
        for (int i = 0; i < 4; i++)
        {
            var arr = new BigInteger[n];
            for (int j = 0; j < n; j++) arr[j] = 1;
            qnp.Add(arr);
        }
        var p = BigInteger.Pow(q, 3) + 1;

        Random rnd = new Random(42);
        int n1 = rnd.Next(0, 1 << 12);
        int n2 = rnd.Next(0, 1 << 12);

        // Timers
        var sw = new Stopwatch();
        long keygenMs = 0, encodeMs = 0, encryptMs = 0, decryptMs = 0, addMs = 0, addDecMs = 0, mulMs = 0, relinMs = 0, mulDecMs = 0;

        for (int iteration = 0; iteration < 10; iteration++)
        {
            // KeyGen timing
            sw.Restart();
            var Evaluator = new BFV(n, q, t, mu, sigma, qnp);
            Evaluator.SecretKeyGen();
            Evaluator.PublicKeyGen();
            Evaluator.EvalKeyGenV1(T);
            Evaluator.EvalKeyGenV2(p);
            sw.Stop();
            keygenMs += sw.ElapsedMilliseconds;

            // Encode
            sw.Restart();
            Poly m1 = Evaluator.IntEncode(n1);
            Poly m2 = Evaluator.IntEncode(n2);
            sw.Stop();
            encodeMs += sw.ElapsedMilliseconds;

            // Encryption timing
            sw.Restart();
            var ct1 = Evaluator.Encryption(m1);
            var ct2 = Evaluator.Encryption(m2);
            sw.Stop();
            encryptMs += sw.ElapsedMilliseconds;

            // Decryption timing
            sw.Restart();
            var dec1 = Evaluator.Decryption(ct1);
            var dec2 = Evaluator.Decryption(ct2);
            sw.Stop();
            decryptMs += sw.ElapsedMilliseconds;

            // Addition timing
            sw.Restart();
            var ct_add = Evaluator.HomomorphicAddition(ct1, ct2);
            sw.Stop();
            addMs += sw.ElapsedMilliseconds;
            sw.Restart();
            var mt_add = Evaluator.Decryption(ct_add);
            sw.Stop();
            addDecMs += sw.ElapsedMilliseconds;

            // Multiplication timing (with relinearization)
            sw.Restart();
            var ct_mul = Evaluator.HomomorphicMultiplication(ct1, ct2);
            sw.Stop();
            mulMs += sw.ElapsedMilliseconds;
            sw.Restart();
            var ct_mul_relin = Evaluator.RelinearizationV1(ct_mul);
            sw.Stop();
            relinMs += sw.ElapsedMilliseconds;
            sw.Restart();
            var mt_mul = Evaluator.Decryption(ct_mul_relin);
            sw.Stop();
            mulDecMs += sw.ElapsedMilliseconds;
        }

        // Calculate mean times
        keygenMs /= 10;
        encodeMs /= 10;
        encryptMs /= 10;
        decryptMs /= 10;
        addMs /= 10;
        addDecMs /= 10;
        mulMs /= 10;
        relinMs /= 10;
        mulDecMs /= 10;

        // Print as table
        Console.WriteLine("| KeyGen | Encrypt | Add | Multiply | Decrypt |");
        Console.WriteLine("|--------|---------|-----|----------|---------|");
        Console.WriteLine($"| {keygenMs,6} | {encryptMs,7} | {addMs,3} | {mulMs + relinMs,8} | {decryptMs + addDecMs + mulDecMs,7} |");
    }
}
