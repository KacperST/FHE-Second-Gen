using System;

public class Rq
{
    public static int Q = 257; // Modulo
    public static int N = 6;   // Stopień pierścienia R_q = Z_q[X]/(X^N + 1)

    public int[] coeffs;

    public Rq(int[] coeffs)
    {
        this.coeffs = ReducePoly(coeffs);
    }

    /// <summary>
    /// Redukuje wielomian modulo (X^N + 1), tzn. X^N ≡ -1 (mod X^N + 1)
    /// </summary>
    private int[] ReducePoly(int[] poly)
    {
        int[] result = new int[N];

        // Skopiuj współczynniki do stopnia N-1 wprost
        int minLen = Math.Min(N, poly.Length);
        for (int i = 0; i < minLen; i++)
        {
            result[i] = ModQ(poly[i]);
        }

        // Redukcja wyższych stopni: X^k ≡ -X^{k−N} (mod X^N + 1)
        for (int i = N; i < poly.Length; i++)
        {
            int targetIndex = i - N;
            result[targetIndex] = ModQ(result[targetIndex] - poly[i]);
        }

        return result;
    }

    public static int ModQ(int value)
    {
        int mod = value % Q;
        return mod < 0 ? mod + Q : mod;
    }

    public static Rq operator +(Rq a, Rq b)
    {
        int[] result = new int[N];
        for (int i = 0; i < N; i++)
        {
            result[i] = ModQ(a.coeffs[i] + b.coeffs[i]);
        }
        return new Rq(result);
    }

    public static Rq operator -(Rq a)
    {
        int[] result = new int[N];
        for (int i = 0; i < N; i++)
        {
            result[i] = ModQ(-a.coeffs[i]);
        }
        return new Rq(result);
    }

    public static Rq operator -(Rq a, Rq b)
    {
        return a + (-b);
    }

    public static Rq operator *(Rq a, Rq b)
    {
        int[] result = new int[2 * N - 1];
        for (int i = 0; i < N; i++)
        {
            for (int j = 0; j < N; j++)
            {
                result[i + j] += a.coeffs[i] * b.coeffs[j];
            }
        }
        return new Rq(result);
    }

    public static Rq operator *(int scalar, Rq a)
    {
        int[] result = new int[N];
        for (int i = 0; i < N; i++)
        {
            result[i] = ModQ(scalar * a.coeffs[i]);
        }
        return new Rq(result);
    }

    /// <summary>
    /// Zwraca wielomian X^degree
    /// </summary>
    public static Rq Monomial(int degree)
    {
        int[] coeffs = new int[degree + 1];
        coeffs[degree] = 1;
        return new Rq(coeffs);
    }

    /// <summary>
    /// Zwraca reprezentację tekstową wielomianu
    /// </summary>
    public override string ToString()
    {
        return string.Join(" + ", coeffs.Select((c, i) => $"{c}*X^{i}"));
    }
}
