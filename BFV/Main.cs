public class Program
{
    public static void Main()
    {
        // Ustaw N=6 przed jakąkolwiek operacją na Rq/BFV
        Rq.SetN(6);
        var bfv = new BFV();

        // Test 1: Dodawanie i mnożenie prostych wiadomości
        var m1arr = new int[Rq.N];
        var m2arr = new int[Rq.N];
        m1arr[0] = 1; // wiadomość = 1
        m2arr[0] = 2; // wiadomość = 2
        var m1 = new Rq(m1arr);
        var m2 = new Rq(m2arr);

        var ct1 = bfv.Encrypt(m1);
        var ct2 = bfv.Encrypt(m2);

        var ct_sum = bfv.Add(ct1, ct2);
        var ct_mul = bfv.Mul(ct1, ct2);
        var decrypted_sum = bfv.Decrypt(ct_sum);
        var decrypted_mul = bfv.Decrypt(ct_mul);

        Console.WriteLine($"Test 1: N = {Rq.N}, t = {BFV.t}, q = {BFV.q}");
        Console.WriteLine($"M1: {m1}");
        Console.WriteLine($"M2: {m2}");
        Console.WriteLine($"Dec(M1 + M2): {decrypted_sum}, plaintext: {m1 + m2}");
        Console.WriteLine($"Dec(M1 * M2): {decrypted_mul}, plaintext: {(m1 * m2) % BFV.t}");

        // Test 2: Dodawanie wielomianów z kilkoma współczynnikami
        var m3arr = new int[Rq.N];
        var m4arr = new int[Rq.N];
        m3arr[0] = 3; m3arr[2] = 4; m3arr[5] = 1;
        m4arr[1] = 2; m4arr[2] = 1; m4arr[4] = 5;
        var m3 = new Rq(m3arr);
        var m4 = new Rq(m4arr);
        var ct3 = bfv.Encrypt(m3);
        var ct4 = bfv.Encrypt(m4);
        var ct3_add_4 = bfv.Add(ct3, ct4);
        var ct3_mul_4 = bfv.Mul(ct3, ct4);
        var dec3_add_4 = bfv.Decrypt(ct3_add_4);
        var dec3_mul_4 = bfv.Decrypt(ct3_mul_4);

        Console.WriteLine("\nTest 2: Wielomiany");
        Console.WriteLine($"M3: {m3}");
        Console.WriteLine($"M4: {m4}");
        Console.WriteLine($"Dec(M3 + M4): {dec3_add_4}, plaintext: {m3 + m4} ");
        Console.WriteLine($"Dec(M3 * M4): {dec3_mul_4}, plaintext: {(m3 * m4) % BFV.t}");


    }
}
