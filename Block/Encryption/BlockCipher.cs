
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Buffers.Binary;

namespace Block.Encryption;

public static class BlockCipher
{
    public const int BlockSize = 16;
    public const int Rounds = 10;

    // Преобразуем пароль в 16-байтовый ключ
    public static byte[] GetKey(string password)
    {
        byte[] hash = SHA256.HashData(
            Encoding.UTF8.GetBytes(password)
        );

        byte[] key = new byte[BlockSize];

        Array.Copy(hash, key, BlockSize);

        return key;
    }


    // Перестановка битов
    private static int[] Perm(int n)
    {
        int[] p = new int[n];

        for (int i = 0; i < n; i++)
            p[i] = (i * 37) % n;

        return p;
    }

    // Применение перестановки
    private static byte[] Permute(byte[] b, int[] perm)
    {
        int n = b.Length * 8;

        byte[] result = new byte[b.Length];

        for (int i = 0; i < n; i++)
        {
            int bit = (b[i / 8] >> (i % 8)) & 1;

            int dst = perm[i];

            int di = dst / 8;
            int sh = dst % 8;

            result[di] |= (byte)(bit << sh);
        }

        return result;
    }

    // Циклический сдвиг битов
    private static byte[] Rotate(byte[] b, int shift)
    {
        int n = b.Length * 8;

        shift = ((shift % n) + n) % n;

        byte[] result = new byte[b.Length];

        for (int i = 0; i < n; i++)
        {
            int bit = (b[i / 8] >> (i % 8)) & 1;

            int dst = (i + shift) % n;

            result[dst / 8] |=
                (byte)(bit << (dst % 8));
        }

        return result;
    }

    // Обработка одного блока
    private static void ProcessBlock(
        byte[] block,
        byte[] key,
        bool encrypt)
    {
        int n = block.Length * 8;

        int[] p = Perm(n);

        int[] inv = new int[n];

        for (int i = 0; i < n; i++)
            inv[p[i]] = i;

        for (int step = 0; step < Rounds; step++)
        {
            int r = encrypt
                ? step
                : Rounds - 1 - step;

            if (encrypt)
            {
                // 1. XOR с ключом
                for (int i = 0; i < BlockSize; i++)
                    block[i] ^= key[(r + i) % key.Length];

                // 2. Перестановка битов
                byte[] tmp = Permute(block, p);

                Buffer.BlockCopy(
                    tmp, 0, block, 0, BlockSize
                );

                // 3. Циклический сдвиг
                tmp = Rotate(block, 3);

                Buffer.BlockCopy(
                    tmp, 0, block, 0, BlockSize
                );
            }
            else
            {
                // Обратный циклический сдвиг
                byte[] tmp = Rotate(block, -3);

                Buffer.BlockCopy(
                    tmp, 0, block, 0, BlockSize
                );

                // Обратная перестановка
                tmp = Permute(block, inv);

                Buffer.BlockCopy(
                    tmp, 0, block, 0, BlockSize
                );

                // Обратный XOR
                for (int i = 0; i < BlockSize; i++)
                    block[i] ^= key[(r + i) % key.Length];
            }
        }
    }

    // Шифрование файла в массив байтов
    public static byte[] Encrypt(
        byte[] data,
        byte[] key,
        string ext)
    {
        byte[] extBytes = Encoding.UTF8.GetBytes(ext ?? "");

        // Заголовок:
        // 4 байта - длина расширения
        // 4 байта - размер исходного файла
        // далее расширение и содержимое файла

        byte[] header = new byte[8 + extBytes.Length];

        BinaryPrimitives.WriteInt32LittleEndian(
            header.AsSpan(0, 4), extBytes.Length
        );

        BinaryPrimitives.WriteInt32LittleEndian(
            header.AsSpan(4, 4), data.Length
        );

        extBytes.CopyTo(header, 8);

        int total = header.Length + data.Length;

        int padding =
            (BlockSize - total % BlockSize) % BlockSize;

        byte[] buffer = new byte[total + padding];

        header.CopyTo(buffer, 0);
        data.CopyTo(buffer, header.Length);

        byte[] result = new byte[buffer.Length];

        byte[] block = new byte[BlockSize];

        for (int i = 0; i < buffer.Length; i += BlockSize)
        {
            Buffer.BlockCopy(
                buffer, i, block, 0, BlockSize
            );

            ProcessBlock(block, key, true);

            Buffer.BlockCopy(
                block, 0, result, i, BlockSize
            );
        }

        return result;
    }

    // Дешифрование массива байтов
    public static byte[] Decrypt(
        byte[] data,
        byte[] key,
        out string ext)
    {
        if (data.Length == 0 ||
            data.Length % BlockSize != 0)
        {
            throw new InvalidDataException(
                "Неверный размер зашифрованного файла."
            );
        }

        byte[] result = new byte[data.Length];

        byte[] block = new byte[BlockSize];

        for (int i = 0; i < data.Length; i += BlockSize)
        {
            Buffer.BlockCopy(
                data, i, block, 0, BlockSize
            );

            ProcessBlock(block, key, false);

            Buffer.BlockCopy(
                block, 0, result, i, BlockSize
            );
        }

        if (result.Length < 8)
            throw new InvalidDataException("Повреждён заголовок.");

        int extLen = BinaryPrimitives.ReadInt32LittleEndian(
            result.AsSpan(0, 4)
        );

        int dataLen = BinaryPrimitives.ReadInt32LittleEndian(
            result.AsSpan(4, 4)
        );

        if (extLen < 0 ||
            dataLen < 0 ||
            8L + extLen + dataLen > result.Length)
        {
            throw new InvalidDataException(
                "Неверный пароль или повреждённые данные."
            );
        }

        ext = Encoding.UTF8.GetString(
            result, 8, extLen
        );

        byte[] decrypted = new byte[dataLen];

        Buffer.BlockCopy(
            result,
            8 + extLen,
            decrypted,
            0,
            dataLen
        );

        return decrypted;
    }
}
