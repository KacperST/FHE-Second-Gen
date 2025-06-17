using System;
using System.Numerics;

public class Helper
{
    public GeneratePrime GeneratePrime { get; set; } = new GeneratePrime();
    public static (BigInteger g, BigInteger x, BigInteger y) Egcd(BigInteger a, BigInteger b)
    {
        if (a == 0)
            return (b, 0, 1);
        var (g, y, x) = Egcd(b % a, a);
        return (g, x - (b / a) * y, y);
    }

    public static BigInteger ModInv(BigInteger a, BigInteger m)
    {
        var (g, x, _) = Helper.Egcd(a, m);
        if (g != 1)
            throw new Exception("Modular inverse does not exist");
        return (x % m + m) % m;
    }
    public static BigInteger Gcd(BigInteger n1, BigInteger n2)
    {
        BigInteger a = n1;
        BigInteger b = n2;
        while (b != 0)
        {
            (a, b) = (b, a % b);
        }
        return a;
    }
    public static int IntReverse(int a, int n)
    {
        string b = Convert.ToString(a, 2).PadLeft(n, '0');
        char[] reversed = b.ToCharArray();
        Array.Reverse(reversed);
        return Convert.ToInt32(new string(reversed), 2);
    }
    public static T[] IndexReverse<T>(T[] a, int r)
    {
        int n = a.Length;
        T[] b = new T[n];
        for (int i = 0; i < n; i++)
        {
            int revIdx = Helper.IntReverse(i, r);
            b[revIdx] = a[i];
        }
        return b;
    }
    public static BigInteger[] RefPolMul(BigInteger[] A, BigInteger[] B, BigInteger M)
    {
        int n = A.Length;
        BigInteger[] C = new BigInteger[2 * n];
        BigInteger[] D = new BigInteger[n];

        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                C[i + j] = (C[i + j] + A[i] * B[j]) % M;
            }
        }

        for (int i = 0; i < n; i++)
        {
            D[i] = (C[i] - C[i + n]) % M;
            if (D[i] < 0) D[i] += M;
        }

        return D;
    }
    public static BigInteger[] RefPolMulv2(BigInteger[] A, BigInteger[] B)
    {
        int n = A.Length;
        BigInteger[] C = new BigInteger[2 * n];
        BigInteger[] D = new BigInteger[n];

        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                C[i + j] += A[i] * B[j];
            }
        }

        for (int i = 0; i < n; i++)
        {
            D[i] = C[i] - C[i + n];
        }

        return D;
    }
    public static bool IsRootOfUnity(BigInteger w, int m, BigInteger q)
    {
        if (w == 0)
            return false;
        else if (BigInteger.ModPow(w, m / 2, q) == q - 1)
            return true;
        else
            return false;
    }
    public static BigInteger GetProperPrime(int n, int logq)
    {
        BigInteger factor = 2 * n;
        BigInteger value = (BigInteger.One << logq) - factor + 1;
        BigInteger lbound = BigInteger.One << (logq - 1);

        while (value > lbound)
        {
            if (GeneratePrime.IsPrime(value))
                return value;
            value -= factor;
        }

        throw new Exception("Failed to find a proper prime.");
    }
    public static (bool, BigInteger) FindPrimitiveRoot(int m, BigInteger q)
{
        BigInteger g = (q - 1) / m;

        if ((q - 1) != g * m)
            return (false, 0);

        int attemptCtr = 0;
        int attemptMax = 100;
        var rng = new Random();

        while (attemptCtr < attemptMax)
        {
            BigInteger a = rng.Next(2, (int)(q - 1));
            BigInteger b = BigInteger.ModPow(a, g, q);

            if (IsRootOfUnity(b, m, q))
                return (true, b);

            attemptCtr++;
        }

        return (true, 0);
    }

    public static (BigInteger q, BigInteger psi, BigInteger psiv, BigInteger w, BigInteger wv) ParamGen(int n, int logq)
    {
        bool pfound = false;
        BigInteger q = 0;
        BigInteger psi = 0;

        while (!pfound)
        {
            q = GetProperPrime(n, logq);
            (pfound, psi) = FindPrimitiveRoot(2 * n, q);
        }

        BigInteger psiv = ModInv(psi, q);
        BigInteger w = BigInteger.ModPow(psi, 2, q);
        BigInteger wv = ModInv(w, q);

        return (q, psi, psiv, w, wv);
    }



}