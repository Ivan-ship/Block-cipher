
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Maui.Storage;


namespace Block.Encryption;

public class FileDecryptor
{
    public async Task<FileSaverResult> DecryptFileAsync(
        FileResult file,
        string password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Введите пароль.");

        // Читаем зашифрованный файл
        byte[] encryptedData;

        using (Stream stream = await file.OpenReadAsync())
        using (MemoryStream memory = new MemoryStream())
        {
            await stream.CopyToAsync(memory, cancellationToken);

            encryptedData = memory.ToArray();
        }

        // Получаем ключ
        byte[] key = BlockCipher.GetKey(password);

        // Расшифровываем файл
        string ext = "";

        byte[] decryptedData = await Task.Run(
            () => BlockCipher.Decrypt(encryptedData, key, out ext),
            cancellationToken
        );

        // Проверяем расширение
        ext = Path.GetExtension("file" + ext);

        // Формируем имя восстановленного файла
        string fileName = "decrypted" + ext;

        // Сохраняем результат
        using (MemoryStream output = new MemoryStream(decryptedData))
        {
            return await FileSaver.Default.SaveAsync(
                fileName,
                output,
                cancellationToken
            );
        }
    }
}
