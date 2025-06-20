using System;
using System.Numerics;
using System.Security.Cryptography;

public class GeneratePrime
{
    static readonly int[] lowPrimes = new int[] {
        3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,
        101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,
        181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,
        271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,
        373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,
        463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,
        577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,
        673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,
        787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,
        887,907,911,919,929,937,941,947,953,967,971,977,983,991,997
    };

    public static bool IsPrime(BigInteger n, int s = 11)
    {
        if (n == 2) return true;
        if (n < 2 || n % 2 == 0) return false;

        foreach (int p in lowPrimes)
        {
            if (n == p)
                return true;
            if (n % p == 0)
                return false;
        }

        return MillerRabin(n, s);
    }

    private static bool MillerRabin(BigInteger n, int s)
    {
        BigInteger r = n - 1;
        int u = 0;
        while ((r & 1) == 0)
        {
            u += 1;
            r /= 2;
        }

        for (int i = 0; i < s; i++)
        {
            BigInteger a = RandomBigInteger(2, n - 2);
            BigInteger z = BigInteger.ModPow(a, r, n);
            if (z != 1 && z != n - 1)
            {
                bool cont = false;
                for (int j = 0; j < u - 1; j++)
                {
                    z = BigInteger.ModPow(z, 2, n);
                    if (z == n - 1)
                    {
                        cont = true;
                        break;
                    }
                    if (z == 1)
                        return false;
                }
                if (!cont) return false;
            }
        }

        return true;
    }

    private static BigInteger RandomBigInteger(BigInteger min, BigInteger max)
    {
        using var rng = RandomNumberGenerator.Create();
        int byteCount = max.ToByteArray().Length;
        byte[] bytes = new byte[byteCount];
        BigInteger result;

        do
        {
            rng.GetBytes(bytes);
            bytes[^1] &= 0x7F; // upewnij się, że liczba jest dodatnia
            result = new BigInteger(bytes);
        } while (result < min || result >= max);

        return result;
    }

    public static BigInteger GenerateLargePrime(int k, int s = 11)
    {
        int maxTries = (int)(100 * (Math.Log(k, 2) + 1));
        while (maxTries-- > 0)
        {
            BigInteger n = RandomBigInteger(BigInteger.One << (k - 1), BigInteger.One << k);
            if (IsPrime(n, s))
                return n;
        }
        throw new Exception($"Failure after {100 * (Math.Log(k, 2) + 1):F0} tries.");
    }
}
