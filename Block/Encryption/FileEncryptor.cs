
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Maui.Storage;

namespace Block.Encryption;

public class FileEncryptor
{
    public async Task<FileSaverResult> EncryptFileAsync(
        FileResult file,
        string password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new ArgumentException("Введите пароль.");

        // Читаем исходный файл
        byte[] fileData;

        using (Stream stream = await file.OpenReadAsync())
        using (MemoryStream memory = new MemoryStream())
        {
            await stream.CopyToAsync(memory, cancellationToken);

            fileData = memory.ToArray();
        }

        // Получаем ключ
        byte[] key = BlockCipher.GetKey(password);

        // Получаем исходное расширение файла
        string ext = Path.GetExtension(file.FileName);

        // Шифруем данные
        byte[] encryptedData = await Task.Run(
            () => BlockCipher.Encrypt(fileData, key, ext),
            cancellationToken
        );

        // Формируем имя результата
        string fileName =
            Path.GetFileNameWithoutExtension(file.FileName)
            + "_encrypted.vault";

        // Сохраняем зашифрованный файл
        using (MemoryStream output = new MemoryStream(encryptedData))
        {
            return await FileSaver.Default.SaveAsync(
                fileName,
                output,
                cancellationToken
            );
        }
    }
}
