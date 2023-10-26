using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

public class Program
{

    class ColumnarTransposition
    {
        // Función para cifrar un mensaje usando la transposición por columna simple
        static string Compresion(string mensaje, string clave)
        {
            int filas = clave.Length;
            int columnas = (int)Math.Ceiling((double)mensaje.Length / filas);

            char[,] matriz = new char[filas, columnas];

            int k = 0;

            for (int i = 0; i < columnas; i++)
            {
                for (int j = 0; j < filas; j++)
                {
                    if (k < mensaje.Length)
                        matriz[j, i] = mensaje[k++];
                    else
                        matriz[j, i] = '_'; // Rellenamos con caracteres vacíos
                }
            }

            StringBuilder cifrado = new StringBuilder();

            for (int i = 0; i < filas; i++)
            {
                for (int j = 0; j < columnas; j++)
                {
                    cifrado.Append(matriz[i, j]);
                }
            }

            return cifrado.ToString();
        }

        // Función para descifrar un mensaje cifrado con transposición por columna simple
        static string Descompresion(string cifrado, string clave)
        {
            int filas = clave.Length;
            int columnas = cifrado.Length / filas;

            char[,] matriz = new char[filas, columnas];

            int k = 0;

            for (int i = 0; i < filas; i++)
            {
                for (int j = 0; j < columnas; j++)
                {
                    matriz[i, j] = cifrado[k++];
                }
            }

            StringBuilder mensaje = new StringBuilder();

            for (int i = 0; i < columnas; i++)
            {
                for (int j = 0; j < filas; j++)
                {
                    mensaje.Append(matriz[j, i]);
                }
            }

            return mensaje.ToString().Replace("_", ""); // Eliminamos caracteres vacíos
        }
        public static class PrivateKey
        {
            public static BigInteger NextBigInteger(int bitLength)
            {
                if (bitLength < 1) return BigInteger.Zero;

                int bytes = bitLength / 8;
                int bits = bitLength % 8;

                // Generates enough random bytes to cover our bits.
                Random rnd = new Random();
                byte[] bs = new byte[bytes + 1];
                rnd.NextBytes(bs);

                // Mask out the unnecessary bits.
                byte mask = (byte)(0xFF >> (8 - bits));
                bs[bs.Length - 1] &= mask;

                return new BigInteger(bs);
            }

            // Random Integer Generator within the given range
            public static BigInteger RandomBigInteger(BigInteger start, BigInteger end)
            {
                if (start == end) return start;

                BigInteger res = end;

                // Swap start and end if given in reverse order.
                if (start > end)
                {
                    end = start;
                    start = res;
                    res = end - start;
                }
                else
                    // The distance between start and end to generate a random BigIntger between 0 and (end-start) (non-inclusive).
                    res -= start;

                byte[] bs = res.ToByteArray();

                // Count the number of bits necessary for res.
                int bits = 8;
                byte mask = 0x7F;
                while ((bs[bs.Length - 1] & mask) == bs[bs.Length - 1])
                {
                    bits--;
                    mask >>= 1;
                }
                bits += 8 * bs.Length;

                // Generate a random BigInteger that is the first power of 2 larger than res, 
                // then scale the range down to the size of res,
                // finally add start back on to shift back to the desired range and return.
                return ((NextBigInteger(bits + 1) * res) / BigInteger.Pow(2, bits + 1)) + start;
            }
        }

        public static class Hash
        {
            public static BigInteger modPow(BigInteger b, BigInteger e, BigInteger m)
            {
                BigInteger result = 1;
                while (e > 0)
                {
                    if ((e & 1) == 1)
                    {
                        result = (result * b) % m;
                    }
                    e = e >> 1;
                    b = (b * b) % m;
                }
                return result;
            }

            public static class PublicKey
            {
                public static BigInteger GeneratePublicKey(BigInteger n, BigInteger k)
                {
                    // Calcula la clave pública a partir de n y k
                    BigInteger publicKey = BigInteger.ModPow(k, 65537, n); // Usamos un exponente público típico (65537)

                    return publicKey;
                }
            }
            public static void Main(string[] args)
        {
            // Convertir el texto a hash con SHA-256
            string texto = "hola como estas";
            byte[] hashTexto = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(texto));

            // Generar una llave privada
            BigInteger j = PrivateKey.NextBigInteger(128);
            BigInteger n = PrivateKey.NextBigInteger(256);

            // Convertir el hash a BigInteger
            BigInteger firmaDigitalBigInt = new BigInteger(hashTexto);

            // Generar la firma digital
            BigInteger firmaDigital = Hash.modPow(firmaDigitalBigInt, j, n);

            // Unir la firma digital con el texto inicial
            string textoFirmado = texto + firmaDigital.ToString();

            // Imprimir el texto firmado en consola
            Console.WriteLine("Texto firmado: " + textoFirmado);



            string clave = "MILLAVE";

            // Cifrar el mensaje
            string compresion = Compresion(texto, clave);
            string compresionfirma = Compresion(firmaDigital.ToString(), clave);

            Console.WriteLine("Compresión Texto: " + compresion);
            Console.WriteLine("Compresión Firma: " + compresionfirma);

            Console.WriteLine(" ");


            // Descifrar el mensaje
            string descompresion = Descompresion(compresion, clave);
            string descompresionfirma = Descompresion(compresionfirma, clave);

            Console.WriteLine("Descompresión: " + descompresion);
            Console.WriteLine("Descompresión firma: " + descompresionfirma);

            Console.WriteLine(" ");

            string textoFirmadoDescomprimido = descompresion + descompresionfirma;
            Console.WriteLine("Texto firmado descomprimido: " + textoFirmadoDescomprimido);


            byte[] hashDescomprimido = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(descompresion));
            BigInteger HashTexto = new BigInteger(hashDescomprimido);
            Console.WriteLine("Hash del texto descifrado: " + HashTexto.ToString());

                // Genera la clave pública a partir de n y k
                BigInteger k = PrivateKey.NextBigInteger(128);
                BigInteger publicKey = PublicKey.GeneratePublicKey(n, k);

                // Descifra la firma con la clave pública
                BigInteger descompresionfirmaBigInt = firmaDigital;

                // Descifra la firma con la clave pública
                BigInteger decryptedSignature = BigInteger.ModPow(descompresionfirmaBigInt, k, n); // Usamos el mismo exponente público

                // Convierte la firma descifrada en un hash
                byte[] hashDecryptedSignature = SHA256.Create().ComputeHash(decryptedSignature.ToByteArray());
                BigInteger hashBigIntFirma = new BigInteger(hashDecryptedSignature);

                // Muestra el hash en la consola
                Console.WriteLine("Hash de la firma descifrada: " + hashBigIntFirma);


                // Compara el hash del texto con el hash de la firma
                if (hashTexto.Equals(hashBigIntFirma))
                {
                    Console.WriteLine("La firma es válida.");
                }
                else
                {
                    Console.WriteLine("La firma es inválida.");
                }


            }
        }
    }
}