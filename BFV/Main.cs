using System;

public class Program
{
    public static void Main(string[] args)
    {
        var bfv = new BFV();

        // Wiadomość do zaszyfrowania
        int[] message1 = new int[BFV.N];
        int[] message2 = new int[BFV.N];

        // Zapełnij wiadomości przykładowymi danymi
        for (int i = 0; i < BFV.N; i++)
        {
            message1[i] = i % BFV.T;          // np. [0,1,2,...,T-1,0,1,...]
            message2[i] = (2 * i) % BFV.T;
        }

        // Szyfrowanie
        var ct1 = bfv.Encrypt(message1);
        var ct2 = bfv.Encrypt(message2);

        // Deszyfrowanie oryginałów
        var dec1 = bfv.Decrypt(ct1);
        var dec2 = bfv.Decrypt(ct2);

        Console.WriteLine("Plaintext 1: " + string.Join(", ", message1));
        Console.WriteLine("Decrypted 1: " + string.Join(", ", dec1));
        Console.WriteLine("Plaintext 2: " + string.Join(", ", message2));
        Console.WriteLine("Decrypted 2: " + string.Join(", ", dec2));

        // Dodawanie szyfrogramów
        var ctAdd = bfv.EvalAdd(ct1, ct2);
        var decAdd = bfv.Decrypt(ctAdd);
        Console.WriteLine("Decrypted Add: " + string.Join(", ", decAdd));

        // Mnożenie szyfrogramów (z relinearizacją)
        var ctMul = bfv.EvalMult(ct1, ct2);
        var decMul = bfv.Decrypt(ctMul);
        Console.WriteLine("Decrypted Mult: " + string.Join(", ", decMul));

        // Test 1: Sprawdzenie poprawności deszyfrowania
        bool ok1 = true, ok2 = true;
        for (int i = 0; i < BFV.N; i++)
        {
            if (message1[i] != dec1[i]) ok1 = false;
            if (message2[i] != dec2[i]) ok2 = false;
        }
        Console.WriteLine(ok1 ? "[OK] Decrypt 1 matches input" : "[FAIL] Decrypt 1 does not match input");
        Console.WriteLine(ok2 ? "[OK] Decrypt 2 matches input" : "[FAIL] Decrypt 2 does not match input");

        // Test 2: Dodawanie - sprawdź poprawność
        bool okAdd = true;
        for (int i = 0; i < BFV.N; i++)
        {
            int expected = (message1[i] + message2[i]) % BFV.T;
            if (decAdd[i] != expected) okAdd = false;
        }
        Console.WriteLine(okAdd ? "[OK] Decrypt Add matches input sum" : "[FAIL] Decrypt Add does not match input sum");

        // Test 3: Mnożenie - sprawdź poprawność
        bool okMul = true;
        for (int i = 0; i < BFV.N; i++)
        {
            int expected = (message1[i] * message2[i]) % BFV.T;
            if (decMul[i] != expected) okMul = false;
        }
        Console.WriteLine(okMul ? "[OK] Decrypt Mult matches input product" : "[FAIL] Decrypt Mult does not match input product");

        // Test 4: Graniczne przypadki (same zera, same T-1)
        int[] zeros = new int[BFV.N];
        int[] maxs = new int[BFV.N];
        for (int i = 0; i < BFV.N; i++) maxs[i] = BFV.T - 1;
        var ctZeros = bfv.Encrypt(zeros);
        var ctMaxs = bfv.Encrypt(maxs);
        var decZeros = bfv.Decrypt(ctZeros);
        var decMaxs = bfv.Decrypt(ctMaxs);
        Console.WriteLine("Zeros decrypted:   " + string.Join(", ", decZeros));
        Console.WriteLine("Maxs decrypted:    " + string.Join(", ", decMaxs));

        // Test 5: Losowe wiadomości
        var rand = new Random();
        int[] randomMsg = new int[BFV.N];
        for (int i = 0; i < BFV.N; i++) randomMsg[i] = rand.Next(BFV.T);
        var ctRand = bfv.Encrypt(randomMsg);
        var decRand = bfv.Decrypt(ctRand);
        bool okRand = true;
        for (int i = 0; i < BFV.N; i++) if (randomMsg[i] != decRand[i]) okRand = false;
        Console.WriteLine(okRand ? "[OK] Decrypt random matches input" : "[FAIL] Decrypt random does not match input");
    }
}
