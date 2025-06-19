using System;

using System.Numerics;

public static class NTT
{
    public static BigInteger[] Transform(BigInteger[] A, BigInteger[] W_table, BigInteger q)
    {
        int n = A.Length;
        BigInteger[] B = new BigInteger[n];
        Array.Copy(A, B, n);

        int v = (int)Math.Log(n, 2);

        for (int i = 0; i < v; i++)
        {
            int pow2i = 1 << i;
            int pow2v_i_1 = 1 << (v - i - 1);

            for (int j = 0; j < pow2i; j++)
            {
                for (int k = 0; k < pow2v_i_1; k++)
                {
                    int s = j * (pow2v_i_1 << 1) + k;
                    int t = s + pow2v_i_1;

                    BigInteger w = W_table[pow2i * k];

                    BigInteger as_temp = B[s];
                    BigInteger at_temp = B[t];

                    B[s] = (as_temp + at_temp) % q;
                    B[t] = ((as_temp - at_temp) * w) % q;
                    if (B[t] < 0) B[t] += q;
                }
            }
        }

        B = Helper.IndexReverse(B, v);

        return B;
    }
     public static BigInteger[] INTT(BigInteger[] A, BigInteger[] W_table, BigInteger q)
    {
        int n = A.Length;
        BigInteger[] B = new BigInteger[n];
        Array.Copy(A, B, n);

        int v = (int)Math.Log(n, 2);

        for (int i = 0; i < v; i++)
        {
            int pow2i = 1 << i;
            int pow2v_i_1 = 1 << (v - i - 1);

            for (int j = 0; j < pow2i; j++)
            {
                for (int k = 0; k < pow2v_i_1; k++)
                {
                    int s = j * (pow2v_i_1 << 1) + k;
                    int t = s + pow2v_i_1;

                    BigInteger w = W_table[pow2i * k];

                    BigInteger as_temp = B[s];
                    BigInteger at_temp = B[t];

                    B[s] = (as_temp + at_temp) % q;
                    B[t] = ((as_temp - at_temp) * w) % q;
                    if (B[t] < 0) B[t] += q;
                }
            }
        }

        B = Helper.IndexReverse(B, v);

        BigInteger n_inv = Helper.ModInv(n, q);
        for (int i = 0; i < n; i++)
        {
            B[i] = B[i] * n_inv % q;
            if (B[i] < 0) B[i] += q;
        }

        return B;
    }
}
