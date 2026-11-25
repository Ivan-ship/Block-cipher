
using System;
using System.Security.Cryptography;
using Block.Encryption;

namespace Block;

public partial class MainPage : ContentPage
{
    private FileResult? encryptFile;
    private FileResult? decryptFile;

    private readonly FileEncryptor encryptor = new();
    private readonly FileDecryptor decryptor = new();

    public MainPage()
    {
        InitializeComponent();
    }

    // Выбор исходного файла
    private async void OnSelectEncryptFileClicked(
        object sender, EventArgs e)
    {
        try
        {
            encryptFile = await FilePicker.Default.PickAsync();

            if (encryptFile != null)
            {
                EncryptFileLabel.Text = encryptFile.FileName;
                StatusLabel.Text = "Исходный файл выбран";
            }
        }
        catch (Exception ex)
        {
            StatusLabel.Text = ex.Message;
        }
    }

    // Выбор зашифрованного файла
    private async void OnSelectDecryptFileClicked(
        object sender, EventArgs e)
    {
        try
        {
            decryptFile = await FilePicker.Default.PickAsync();

            if (decryptFile != null)
            {
                DecryptFileLabel.Text = decryptFile.FileName;
                StatusLabel.Text = "Зашифрованный файл выбран";
            }
        }
        catch (Exception ex)
        {
            StatusLabel.Text = ex.Message;
        }
    }

    // Показать / скрыть пароль шифрования
    private void OnToggleEncryptPasswordClicked(
        object sender, EventArgs e)
    {
        EncryptPassword.IsPassword =
            !EncryptPassword.IsPassword;
    }

    // Показать / скрыть пароль дешифрования
    private void OnToggleDecryptPasswordClicked(
        object sender, EventArgs e)
    {
        DecryptPassword.IsPassword =
            !DecryptPassword.IsPassword;
    }

    // Генерация случайного пароля
    private void OnGeneratePasswordClicked(
        object sender, EventArgs e)
    {
        byte[] randomBytes =
            RandomNumberGenerator.GetBytes(16);

        EncryptPassword.Text =
            Convert.ToHexString(randomBytes);
    }

    // Шифрование
    private async void OnEncryptClicked(
        object sender, EventArgs e)
    {
        if (encryptFile == null)
        {
            StatusLabel.Text = "Выберите файл!";
            return;
        }

        string password = EncryptPassword.Text ?? "";

        if (string.IsNullOrWhiteSpace(password))
        {
            StatusLabel.Text = "Введите пароль!";
            return;
        }

        try
        {
            StatusLabel.Text = "Выполняется шифрование...";

            var result = await encryptor.EncryptFileAsync(
                encryptFile,
                password
            );

            if (result.IsSuccessful)
            {
                StatusLabel.Text =
                    "Файл успешно зашифрован и сохранён!";
            }
            else
            {
                StatusLabel.Text = "Сохранение отменено.";
            }
        }
        catch (Exception ex)
        {
            StatusLabel.Text = "Ошибка: " + ex.Message;
        }
    }

    // Дешифрование
    private async void OnDecryptClicked(
        object sender, EventArgs e)
    {
        if (decryptFile == null)
        {
            StatusLabel.Text = "Выберите файл!";
            return;
        }

        string password = DecryptPassword.Text ?? "";

        if (string.IsNullOrWhiteSpace(password))
        {
            StatusLabel.Text = "Введите пароль!";
            return;
        }

        try
        {
            StatusLabel.Text = "Выполняется дешифрование...";

            var result = await decryptor.DecryptFileAsync(
                decryptFile,
                password
            );

            if (result.IsSuccessful)
            {
                StatusLabel.Text =
                    "Файл успешно расшифрован и сохранён!";
            }
            else
            {
                StatusLabel.Text = "Сохранение отменено.";
            }
        }
        catch (Exception ex)
        {
            StatusLabel.Text = "Ошибка: " + ex.Message;
        }
    }
}
