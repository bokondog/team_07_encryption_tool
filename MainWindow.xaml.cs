using Microsoft.Win32; // For OpenFileDialog
using System;
using System.Collections.Generic;
using System.Diagnostics; // For Stopwatch
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media; // For Brushes
using WinForms = System.Windows.Forms;


namespace TestCryption
{
    public partial class MainWindow : Window
    {
        private string _defaultKeyFolder = string.Empty;
        private string _defaultCiphertextFolder = string.Empty;
        private string _defaultImageFolder = string.Empty;
        private string _defaultEncryptedAesFolder = string.Empty;

        private const string AesSuffix = "_aes.txt";
        private const string RsaSuffix = "_rsa.xml";
        private const string CiphertextSuffix = ".txt";
        private const string EncryptedAesKeySuffix = ".txt"; // Encrypted AES keys saved as .txt
        private const string DecryptedAesKeyPrefix = "decrypted_";
        private const string GeneratedAesKeyPrefix = "generated_";

        // Standard AES block size in bytes (used for IV)
        private const int AesBlockSizeInBytes = 16; // 128 bits / 8 bits/byte

        // Hashing algorithm instance (reusable) - Use SHA256 consistently
        private static readonly HashAlgorithmName _hashAlgorithmName = HashAlgorithmName.SHA256;
        // Note: For performance with large files, you might create instances within methods
        // using 'using var sha256 = SHA256.Create();' instead of reusing a single static instance if thread safety becomes complex.
        // However, for this UI-driven app, creating per-operation is fine.

        public MainWindow()
        {
            InitializeComponent();
            LoadSettings(); // Load all settings
            RefreshAllLists(); // Initial load for keys and ciphertext lists
            DecryptOutputFormatComboBox.SelectedIndex = 0; // Default to .png
        }

        // --- Settings Loading/Saving ---

        private void LoadSettings()
        {
            // Key Folder
            _defaultKeyFolder = Properties.Settings.Default.DefaultKeyFolderPath;
            DefaultFolderTextBox.Text = _defaultKeyFolder; // Always show, even if invalid

            // Ciphertext Folder
            _defaultCiphertextFolder = Properties.Settings.Default.DefaultCiphertextFolderPath;
            CiphertextFolderTextBox.Text = _defaultCiphertextFolder;

            // Image Folder
            _defaultImageFolder = Properties.Settings.Default.DefaultImageFolderPath;
            ImageFolderTextBox.Text = _defaultImageFolder;

            // Encrypted AES Key Folder (New)
            _defaultEncryptedAesFolder = Properties.Settings.Default.DefaultEncryptedAesFolderPath;
            EncryptedAesFolderTextBox.Text = _defaultEncryptedAesFolder;


            // Initial status check - can be more specific if needed
            if (string.IsNullOrWhiteSpace(_defaultKeyFolder) || !Directory.Exists(_defaultKeyFolder) ||
               string.IsNullOrWhiteSpace(_defaultCiphertextFolder) || !Directory.Exists(_defaultCiphertextFolder) ||
               string.IsNullOrWhiteSpace(_defaultImageFolder) || !Directory.Exists(_defaultImageFolder) ||
               string.IsNullOrWhiteSpace(_defaultEncryptedAesFolder) || !Directory.Exists(_defaultEncryptedAesFolder))
            {
                UpdateStatus("Tip: Set and verify default folders in Settings and Encryption tabs.");
            }
            else
            {
                UpdateStatus("Settings loaded.");
            }
        }

        // Updated Save method to include the new path
        private void SaveSettings()
        {
            Properties.Settings.Default.DefaultKeyFolderPath = _defaultKeyFolder;
            Properties.Settings.Default.DefaultCiphertextFolderPath = _defaultCiphertextFolder;
            Properties.Settings.Default.DefaultImageFolderPath = _defaultImageFolder;
            Properties.Settings.Default.DefaultEncryptedAesFolderPath = _defaultEncryptedAesFolder; // New
            Properties.Settings.Default.Save();
        }

        // --- Browse Button Handlers ---

        private void BrowseKeyFolderButton_Click(object sender, RoutedEventArgs e)
        {
            string selectedFolder = BrowseForFolder("Select Default Folder for Keys", _defaultKeyFolder);
            if (!string.IsNullOrEmpty(selectedFolder))
            {
                _defaultKeyFolder = selectedFolder;
                DefaultFolderTextBox.Text = _defaultKeyFolder;
                SaveSettings();
                RefreshKeyList(); // Refresh lists dependent on this folder
                UpdateStatus($"Key folder set to: {_defaultKeyFolder}");
            }
        }

        private void BrowseCiphertextFolderButton_Click(object sender, RoutedEventArgs e)
        {
            string selectedFolder = BrowseForFolder("Select Default Folder for Image Ciphertext Files", _defaultCiphertextFolder);
            if (!string.IsNullOrEmpty(selectedFolder))
            {
                _defaultCiphertextFolder = selectedFolder;
                CiphertextFolderTextBox.Text = _defaultCiphertextFolder;
                SaveSettings();
                RefreshCiphertextList(); // Refresh list dependent on this folder
                UpdateStatus($"Image Ciphertext folder set to: {_defaultCiphertextFolder}");
            }
        }

        private void BrowseImageFolderButton_Click(object sender, RoutedEventArgs e)
        {
            string selectedFolder = BrowseForFolder("Select Default Folder for Decrypted Images", _defaultImageFolder);
            if (!string.IsNullOrEmpty(selectedFolder))
            {
                _defaultImageFolder = selectedFolder;
                ImageFolderTextBox.Text = _defaultImageFolder;
                SaveSettings();
                UpdateStatus($"Decrypted image folder set to: {_defaultImageFolder}");
            }
        }

        private void BrowseEncryptedAesFolderButton_Click(object sender, RoutedEventArgs e) // New
        {
            string selectedFolder = BrowseForFolder("Select Default Folder for Encrypted AES Keys", _defaultEncryptedAesFolder);
            if (!string.IsNullOrEmpty(selectedFolder))
            {
                _defaultEncryptedAesFolder = selectedFolder;
                EncryptedAesFolderTextBox.Text = _defaultEncryptedAesFolder;
                SaveSettings();
                RefreshEncryptedAesKeyList(); // Refresh list dependent on this folder
                UpdateStatus($"Encrypted AES Key folder set to: {_defaultEncryptedAesFolder}");
            }
        }

        private void BrowseEncryptImageButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = "Select Image to Encrypt",
                Filter = "Image Files|*.png;*.jpg;*.jpeg;*.bmp;*.gif|All files (*.*)|*.*"
            };
            if (openFileDialog.ShowDialog() == true)
            {
                EncryptImageSourceTextBox.Text = openFileDialog.FileName;
            }
        }

        private void BrowseHashFile1Button_Click(object sender, RoutedEventArgs e)
        {
            string filePath = BrowseForFile("Select First File for Hashing");
            if (!string.IsNullOrEmpty(filePath))
            {
                HashFile1TextBox.Text = filePath;
                // Clear results when file changes
                HashFile1ResultTextBox.Clear();
                HashComparisonResultTextBlock.Text = "";
            }
        }

        private void BrowseHashFile2Button_Click(object sender, RoutedEventArgs e)
        {
            string filePath = BrowseForFile("Select Second File for Hashing");
            if (!string.IsNullOrEmpty(filePath))
            {
                HashFile2TextBox.Text = filePath;
                // Clear results when file changes
                HashFile2ResultTextBox.Clear();
                HashComparisonResultTextBlock.Text = "";
            }
        }

        // Helper for browsing single files
        private string BrowseForFile(string title)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Title = title,
                Filter = "All files (*.*)|*.*" // Allow any file type for hashing
            };
            return openFileDialog.ShowDialog() == true ? openFileDialog.FileName : null;
        }

        private string BrowseForFolder(string description, string initialPath)
        {
            var dialog = new WinForms.FolderBrowserDialog { Description = description };
            if (!string.IsNullOrWhiteSpace(initialPath) && Directory.Exists(initialPath))
            {
                dialog.SelectedPath = initialPath;
            }
            return dialog.ShowDialog() == WinForms.DialogResult.OK ? dialog.SelectedPath : null;
        }


        // --- Key Generation Handlers (Unchanged) ---
        private void GenerateAesButton_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateKeyGenInput(AesKeyNameTextBox.Text, isRsa: false)) return;

            string keyName = AesKeyNameTextBox.Text.Trim();
            string fileName = GeneratedAesKeyPrefix + keyName + AesSuffix;
            string filePath = Path.Combine(_defaultKeyFolder, fileName);

            if (File.Exists(filePath))
            {
                var result = System.Windows.MessageBox.Show($"File '{fileName}' already exists. Overwrite?", "Confirm Overwrite", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.No)
                {
                    UpdateStatus("AES key generation cancelled.");
                    return;
                }
            }

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.GenerateKey();
                    aes.GenerateIV();

                    string keyBase64 = Convert.ToBase64String(aes.Key);
                    string ivBase64 = Convert.ToBase64String(aes.IV);
                    string fileContent = $"Key={keyBase64}{Environment.NewLine}IV={ivBase64}";
                    File.WriteAllText(filePath, fileContent, Encoding.UTF8);

                    UpdateStatus($"AES Key '{keyName}' saved to {fileName}");
                    AesKeyNameTextBox.Clear();
                    RefreshKeyList(); // Refresh lists
                }
            }
            catch (Exception ex)
            {
                HandleError($"Error generating/saving AES key: {ex.Message}");
            }
        }

        private void GenerateRsaButton_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateKeyGenInput(RsaKeyNameTextBox.Text, isRsa: true)) return;

            string keyName = RsaKeyNameTextBox.Text.Trim();
            string fileName = keyName + RsaSuffix;
            string filePath = Path.Combine(_defaultKeyFolder, fileName);

            if (File.Exists(filePath))
            {
                var result = System.Windows.MessageBox.Show($"File '{fileName}' already exists. Overwrite?", "Confirm Overwrite", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.No)
                {
                    UpdateStatus("RSA key generation cancelled.");
                    return;
                }
            }

            try
            {
                using (RSA rsa = new RSACng(2048)) // Specify key size on creation
                {
                    string publicPrivateKeyXml = rsa.ToXmlString(true);
                    File.WriteAllText(filePath, publicPrivateKeyXml, Encoding.UTF8);

                    UpdateStatus($"RSA Key Pair '{keyName}' saved to {fileName}");
                    RsaKeyNameTextBox.Clear();
                    RefreshKeyList(); // Refresh lists
                }
            }
            catch (Exception ex)
            {
                HandleError($"Error generating/saving RSA key pair: {ex.Message}");
            }
        }


        // --- List Refreshing ---

        private void RefreshKeyListButton_Click(object sender, RoutedEventArgs e)
        { RefreshKeyList(); UpdateStatus("Key list refreshed."); }
        private void RefreshCiphertextListButton_Click(object sender, RoutedEventArgs e)
        { RefreshCiphertextList(); UpdateStatus("Image ciphertext list refreshed."); }
        private void RefreshEncryptedAesListButton_Click(object sender, RoutedEventArgs e) // New
        { RefreshEncryptedAesKeyList(); UpdateStatus("Encrypted AES key list refreshed."); }


        private void RefreshAllLists()
        {
            RefreshKeyList();
            RefreshCiphertextList();
            RefreshEncryptedAesKeyList(); // New
        }

        // Modified RefreshKeyList to populate new RSA ComboBoxes as well
        private void RefreshKeyList()
        {
            KeyListView.Items.Clear();
            // Clear ComboBoxes that use keys across tabs
            EncryptAesKeyComboBox.ItemsSource = null; EncryptAesKeyComboBox.Items.Clear();
            DecryptAesKeyComboBox.ItemsSource = null; DecryptAesKeyComboBox.Items.Clear();
            EncryptRsaAesKeyComboBox.ItemsSource = null; EncryptRsaAesKeyComboBox.Items.Clear();
            EncryptRsaPublicKeyComboBox.ItemsSource = null; EncryptRsaPublicKeyComboBox.Items.Clear();
            DecryptRsaPrivateKeyComboBox.ItemsSource = null; DecryptRsaPrivateKeyComboBox.Items.Clear();


            if (!IsFolderValid(_defaultKeyFolder, null)) return; // Don't show error if folder just not set yet

            try
            {
                var keyFiles = new List<KeyInfo>();
                var aesKeyFiles = new List<KeyInfo>();
                var rsaKeyFiles = new List<KeyInfo>(); // List for RSA keys

                var files = Directory.GetFiles(_defaultKeyFolder);

                foreach (string file in files)
                {
                    string fileName = Path.GetFileName(file);
                    string keyType = null;
                    string keyName = null;

                    if (fileName.EndsWith(AesSuffix, StringComparison.OrdinalIgnoreCase))
                    {
                        keyType = "AES";
                        keyName = fileName.Substring(0, fileName.Length - AesSuffix.Length);
                    }
                    else if (fileName.EndsWith(RsaSuffix, StringComparison.OrdinalIgnoreCase))
                    {
                        keyType = "RSA";
                        keyName = fileName.Substring(0, fileName.Length - RsaSuffix.Length);
                    }

                    if (!string.IsNullOrEmpty(keyType) && !string.IsNullOrEmpty(keyName))
                    {
                        var keyInfo = new KeyInfo { Name = keyName, Type = keyType, FilePath = file };
                        keyFiles.Add(keyInfo);
                        if (keyType == "AES") { aesKeyFiles.Add(keyInfo); }
                        if (keyType == "RSA") { rsaKeyFiles.Add(keyInfo); }
                    }
                }

                keyFiles = keyFiles.OrderBy(k => k.Name).ToList();
                aesKeyFiles = aesKeyFiles.OrderBy(k => k.Name).ToList();
                rsaKeyFiles = rsaKeyFiles.OrderBy(k => k.Name).ToList(); // Sort RSA keys

                // Populate main list view
                foreach (var keyInfo in keyFiles) { KeyListView.Items.Add(keyInfo); }

                // Populate ComboBoxes on Image Tab
                EncryptAesKeyComboBox.ItemsSource = aesKeyFiles;
                DecryptAesKeyComboBox.ItemsSource = aesKeyFiles;
                // Populate ComboBoxes on AES Key Encryption Tab
                EncryptRsaAesKeyComboBox.ItemsSource = aesKeyFiles;
                EncryptRsaPublicKeyComboBox.ItemsSource = rsaKeyFiles;
                DecryptRsaPrivateKeyComboBox.ItemsSource = rsaKeyFiles;

            }
            catch (Exception ex)
            {
                HandleError($"Error reading key directory: {ex.Message}");
            }
        }

        private void RefreshCiphertextList() // Image Ciphertext
        {
            DecryptCiphertextComboBox.ItemsSource = null; DecryptCiphertextComboBox.Items.Clear();
            if (!IsFolderValid(_defaultCiphertextFolder, null)) return;

            try
            {
                var ciphertextFiles = Directory.GetFiles(_defaultCiphertextFolder, $"*{CiphertextSuffix}")
                                               .Where(f => !f.EndsWith(AesSuffix, StringComparison.OrdinalIgnoreCase) && // Exclude actual keys
                                                           !f.EndsWith(RsaSuffix, StringComparison.OrdinalIgnoreCase)) // Exclude actual keys
                                               .Select(f => new FileInfoSimple { Name = Path.GetFileName(f), FilePath = f })
                                               .OrderBy(f => f.Name)
                                               .ToList();
                DecryptCiphertextComboBox.ItemsSource = ciphertextFiles;
            }
            catch (Exception ex) { HandleError($"Error reading image ciphertext directory: {ex.Message}"); }
        }

        // New refresh method for the encrypted AES key list
        private void RefreshEncryptedAesKeyList()
        {
            DecryptRsaEncryptedAesKeyComboBox.ItemsSource = null; DecryptRsaEncryptedAesKeyComboBox.Items.Clear();
            if (!IsFolderValid(_defaultEncryptedAesFolder, null)) return;

            try
            {
                // Assuming these are also .txt files. Adjust filter if needed.
                var encryptedKeyFiles = Directory.GetFiles(_defaultEncryptedAesFolder, $"*{EncryptedAesKeySuffix}")
                                               .Select(f => new FileInfoSimple { Name = Path.GetFileName(f), FilePath = f })
                                               .OrderBy(f => f.Name)
                                               .ToList();
                DecryptRsaEncryptedAesKeyComboBox.ItemsSource = encryptedKeyFiles;
            }
            catch (Exception ex) { HandleError($"Error reading encrypted AES key directory: {ex.Message}"); }
        }


        // --- Image Encryption / Decryption Logic ---
        private async void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            // --- Input Validation ---
            if (!IsFolderValid(_defaultCiphertextFolder, "Ciphertext output folder not set or invalid.")) return;
            if (string.IsNullOrWhiteSpace(EncryptImageSourceTextBox.Text) || !File.Exists(EncryptImageSourceTextBox.Text))
            { HandleError("Please select a valid image file to encrypt."); return; }
            if (EncryptAesKeyComboBox.SelectedItem == null)
            { HandleError("Please select an AES key for encryption."); return; }
            if (string.IsNullOrWhiteSpace(EncryptOutputFilenameTextBox.Text))
            { HandleError("Please enter an output filename for the ciphertext."); return; }
            if (EncryptOutputFilenameTextBox.Text.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            { HandleError($"Output filename '{EncryptOutputFilenameTextBox.Text}' contains invalid characters."); return; }

            string sourceImagePath = EncryptImageSourceTextBox.Text;
            string aesKeyPath = EncryptAesKeyComboBox.SelectedValue as string;
            string outputFileName = EncryptOutputFilenameTextBox.Text.Trim();
            // Ensure output has .txt extension for consistency (as we save Base64)
            if (!outputFileName.EndsWith(CiphertextSuffix, StringComparison.OrdinalIgnoreCase))
            {
                outputFileName += CiphertextSuffix;
            }
            string outputCiphertextPath = Path.Combine(_defaultCiphertextFolder, outputFileName);


            if (File.Exists(outputCiphertextPath))
            {
                var result = System.Windows.MessageBox.Show($"File '{outputFileName}' already exists in the ciphertext folder. Overwrite?", "Confirm Overwrite", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.No)
                {
                    UpdateStatus("Encryption cancelled.");
                    return;
                }
            }

            UpdateStatus("Encrypting...");
            EncryptButton.IsEnabled = false; // Prevent multi-click

            try
            {
                // Load Key/IV
                (byte[] key, byte[] iv) = LoadAesKeyFromFile(aesKeyPath);
                if (key == null || iv == null) return; // Error handled in LoadAesKeyFromFile

                // Read image data
                byte[] imageBytes = File.ReadAllBytes(sourceImagePath);

                // Encrypt
                byte[] encryptedBytes;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                    using (MemoryStream msEncrypt = new MemoryStream())
                    {
                        using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            await csEncrypt.WriteAsync(imageBytes, 0, imageBytes.Length);
                            csEncrypt.FlushFinalBlock(); // Ensure padding is written
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }

                // Convert to Base64 and save
                string base64Encrypted = Convert.ToBase64String(encryptedBytes);
                File.WriteAllText(outputCiphertextPath, base64Encrypted, Encoding.UTF8);

                UpdateStatus($"Image encrypted successfully to {outputFileName}");
                EncryptImageSourceTextBox.Clear();
                EncryptOutputFilenameTextBox.Clear();
                EncryptAesKeyComboBox.SelectedIndex = -1; // Clear selection
                RefreshCiphertextList(); // Update list as we added a file
            }
            catch (Exception ex)
            {
                HandleError($"Encryption failed: {ex.Message}");
            }
            finally
            {
                EncryptButton.IsEnabled = true; // Re-enable button
            }
        }

        private async void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            // --- Input Validation (Unchanged) ---
            if (!IsFolderValid(_defaultImageFolder, "Decrypted image output folder not set or invalid.")) return;
            if (DecryptCiphertextComboBox.SelectedItem == null) { HandleError("Select a ciphertext file."); return; }
            if (DecryptAesKeyComboBox.SelectedItem == null) { HandleError("Select an AES key."); return; }
            if (string.IsNullOrWhiteSpace(DecryptOutputFilenameTextBox.Text)) { HandleError("Enter an output filename."); return; }
            if (HasInvalidFilenameChars(DecryptOutputFilenameTextBox.Text)) { HandleError("Output filename has invalid chars."); return; }
            if (DecryptOutputFormatComboBox.SelectedItem == null) { HandleError("Select output format."); return; }

            // Clear previous hash result
            DecryptedFileHashTextBox.Clear();

            string ciphertextPath = DecryptCiphertextComboBox.SelectedValue as string;
            string aesKeyPath = DecryptAesKeyComboBox.SelectedValue as string;
            string outputFileName = DecryptOutputFilenameTextBox.Text.Trim();
            string outputFormat = (DecryptOutputFormatComboBox.SelectedItem as ComboBoxItem)?.Content as string ?? ".png";
            string outputImagePath = Path.Combine(_defaultImageFolder, outputFileName + outputFormat);

            if (File.Exists(outputImagePath))
            {
                var result = MessageBox.Show($"File '{outputFileName + outputFormat}' exists. Overwrite?", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.No) { UpdateStatus("Decryption cancelled."); return; }
            }

            UpdateStatus("Decrypting...");
            DecryptButton.IsEnabled = false;

            string calculatedHash = null; // Variable to store hash after saving

            try
            {
                // --- Decryption Logic (Unchanged) ---
                (byte[] key, byte[] iv) = LoadAesKeyFromFile(aesKeyPath);
                if (key == null || iv == null) return;
                string base64Encrypted = File.ReadAllText(ciphertextPath);
                byte[] encryptedBytes = Convert.FromBase64String(base64Encrypted);
                byte[] decryptedBytes;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key; aes.IV = iv;
                    ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                    {
                        using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (MemoryStream msPlain = new MemoryStream())
                            {
                                await csDecrypt.CopyToAsync(msPlain);
                                decryptedBytes = msPlain.ToArray();
                            }
                        }
                    }
                }

                // --- Save decrypted bytes (Unchanged) ---
                File.WriteAllBytes(outputImagePath, decryptedBytes);

                // *** NEW: Calculate hash of the saved decrypted file ***
                UpdateStatus("Calculating hash of decrypted file...");
                calculatedHash = CalculateFileHashAsync(outputImagePath); // Use helper
                if (calculatedHash != null)
                {
                    DecryptedFileHashTextBox.Text = calculatedHash; // Display hash
                    UpdateStatus($"Image decrypted to {Path.GetFileName(outputImagePath)} | Hash Calculated");
                }
                else
                {
                    // Error handled in CalculateFileHashAsync, but update status here
                    UpdateStatus($"Image decrypted to {Path.GetFileName(outputImagePath)} | Hash calculation failed.");
                }

                // Clear inputs on success
                DecryptCiphertextComboBox.SelectedIndex = -1;
                DecryptAesKeyComboBox.SelectedIndex = -1;
                DecryptOutputFilenameTextBox.Clear();

            }
            catch (CryptographicException cryptoEx) { HandleError($"Decryption failed. Wrong key or corrupted data? {cryptoEx.Message}"); }
            catch (FormatException formatEx) { HandleError($"Decryption failed. Invalid Base64 data? {formatEx.Message}"); }
            catch (Exception ex) { HandleError($"Decryption failed: {ex.Message}"); }
            finally { DecryptButton.IsEnabled = true; }
        }


        // --- AES Key Encryption / Decryption Logic ---

        private async void EncryptAesKeyButton_Click(object sender, RoutedEventArgs e)
        {
            // --- Input Validation ---
            if (!IsFolderValid(_defaultEncryptedAesFolder, "Encrypted AES Key output folder not set or invalid.")) return;
            if (EncryptRsaAesKeyComboBox.SelectedItem == null) { HandleError("Select an AES key to encrypt."); return; }
            if (EncryptRsaPublicKeyComboBox.SelectedItem == null) { HandleError("Select an RSA public key for encryption."); return; }
            if (string.IsNullOrWhiteSpace(EncryptRsaOutputFilenameTextBox.Text)) { HandleError("Enter an output filename for the encrypted AES key."); return; }
            if (HasInvalidFilenameChars(EncryptRsaOutputFilenameTextBox.Text)) { HandleError("Output filename contains invalid characters."); return; }

            string aesKeyPath = EncryptRsaAesKeyComboBox.SelectedValue as string;
            string rsaKeyPath = EncryptRsaPublicKeyComboBox.SelectedValue as string;
            string outputFileName = EncryptRsaOutputFilenameTextBox.Text.Trim() + EncryptedAesKeySuffix; // Ensure .txt
            string outputEncryptedKeyPath = Path.Combine(_defaultEncryptedAesFolder, outputFileName);

            if (File.Exists(outputEncryptedKeyPath))
            {
                var result = MessageBox.Show($"File '{outputFileName}' already exists. Overwrite?", "Confirm Overwrite", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.No) { UpdateStatus("AES Key encryption cancelled."); return; }
            }

            UpdateStatus("Encrypting AES key...");
            EncryptAesKeyButton.IsEnabled = false; // Disable button

            try
            {
                // 1. Load AES Key & IV
                (byte[] aesKey, byte[] aesIv) = LoadAesKeyFromFile(aesKeyPath);
                if (aesKey == null || aesIv == null) return; // Error handled in helper

                // Ensure IV is expected size (important for decryption splitting)
                if (aesIv.Length != AesBlockSizeInBytes)
                {
                    HandleError($"AES Key file '{Path.GetFileName(aesKeyPath)}' has an unexpected IV size ({aesIv.Length} bytes). Expected {AesBlockSizeInBytes} bytes.");
                    return;
                }

                // 2. Load RSA Public Key
                using (RSA rsa = LoadRsaKeyFromFile(rsaKeyPath, requirePrivateKey: false))
                {
                    if (rsa == null) return; // Error handled in helper

                    // 3. Combine IV and Key (IV first for easy splitting)
                    byte[] combinedData = aesIv.Concat(aesKey).ToArray();

                    // 4. Encrypt using RSA (OAEP padding recommended)
                    byte[] encryptedData = rsa.Encrypt(combinedData, RSAEncryptionPadding.OaepSHA256);

                    // 5. Convert to Base64 and Save
                    string base64Encrypted = Convert.ToBase64String(encryptedData);
                    File.WriteAllText(outputEncryptedKeyPath, base64Encrypted, Encoding.UTF8);

                    UpdateStatus($"AES Key encrypted successfully to {outputFileName}");
                    EncryptRsaAesKeyComboBox.SelectedIndex = -1;
                    EncryptRsaPublicKeyComboBox.SelectedIndex = -1;
                    EncryptRsaOutputFilenameTextBox.Clear();
                    RefreshEncryptedAesKeyList(); // Update list of encrypted keys
                }
            }
            catch (Exception ex)
            {
                HandleError($"AES Key encryption failed: {ex.Message}");
            }
            finally { EncryptAesKeyButton.IsEnabled = true; } // Re-enable button
        }


        private async void DecryptAesKeyButton_Click(object sender, RoutedEventArgs e)
        {
            // --- Input Validation ---
            if (!IsFolderValid(_defaultKeyFolder, "Main Key Folder (for output) not set or invalid. Check Key Management tab.")) return;
            if (DecryptRsaEncryptedAesKeyComboBox.SelectedItem == null) { HandleError("Select an encrypted AES key file to decrypt."); return; }
            if (DecryptRsaPrivateKeyComboBox.SelectedItem == null) { HandleError("Select an RSA private key for decryption."); return; }
            if (string.IsNullOrWhiteSpace(DecryptRsaOutputFilenameTextBox.Text)) { HandleError("Enter an output name for the decrypted AES key."); return; }
            if (HasInvalidFilenameChars(DecryptRsaOutputFilenameTextBox.Text)) { HandleError("Output key name contains invalid characters."); return; }


            string encryptedKeyPath = DecryptRsaEncryptedAesKeyComboBox.SelectedValue as string;
            string rsaKeyPath = DecryptRsaPrivateKeyComboBox.SelectedValue as string;
            string outputKeyName = DecryptedAesKeyPrefix + DecryptRsaOutputFilenameTextBox.Text.Trim();
            string outputDecryptedKeyPath = Path.Combine(_defaultKeyFolder, outputKeyName + AesSuffix); // Save to main key folder

            if (File.Exists(outputDecryptedKeyPath))
            {
                var result = MessageBox.Show($"AES Key file '{outputKeyName + AesSuffix}' already exists in the main key folder. Overwrite?", "Confirm Overwrite", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (result == MessageBoxResult.No) { UpdateStatus("AES Key decryption cancelled."); return; }
            }

            UpdateStatus("Decrypting AES key...");
            DecryptAesKeyButton.IsEnabled = false; // Disable button

            try
            {
                // 1. Load RSA Private Key
                using (RSA rsa = LoadRsaKeyFromFile(rsaKeyPath, requirePrivateKey: true)) // MUST have private key
                {
                    if (rsa == null) return; // Error handled in helper

                    // 2. Read Encrypted Key File (Base64)
                    string base64Encrypted = File.ReadAllText(encryptedKeyPath);
                    byte[] encryptedData = Convert.FromBase64String(base64Encrypted);

                    // 3. Decrypt using RSA
                    byte[] decryptedCombinedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);

                    // 4. Split IV and Key
                    if (decryptedCombinedData.Length <= AesBlockSizeInBytes)
                    {
                        HandleError("Decryption failed: Decrypted data is too short to contain a valid Key and IV.");
                        return; // Exit before erroring on Skip/Take
                    }
                    byte[] aesIv = decryptedCombinedData.Take(AesBlockSizeInBytes).ToArray();
                    byte[] aesKey = decryptedCombinedData.Skip(AesBlockSizeInBytes).ToArray();

                    // 5. Format and Save Decrypted AES Key
                    string keyBase64 = Convert.ToBase64String(aesKey);
                    string ivBase64 = Convert.ToBase64String(aesIv);
                    string fileContent = $"Key={keyBase64}{Environment.NewLine}IV={ivBase64}";

                    File.WriteAllText(outputDecryptedKeyPath, fileContent, Encoding.UTF8);

                    UpdateStatus($"AES Key decrypted successfully to {outputKeyName + AesSuffix}");
                    DecryptRsaEncryptedAesKeyComboBox.SelectedIndex = -1;
                    DecryptRsaPrivateKeyComboBox.SelectedIndex = -1;
                    DecryptRsaOutputFilenameTextBox.Clear();
                    RefreshKeyList(); // Update main list as we added a new AES key
                }
            }
            catch (CryptographicException cryptoEx)
            {
                HandleError($"AES Key decryption failed. Likely wrong RSA private key or corrupted data. Details: {cryptoEx.Message}");
            }
            catch (FormatException formatEx)
            { HandleError($"Decryption failed. Encrypted key file does not contain valid Base64 data. Details: {formatEx.Message}"); }
            catch (Exception ex)
            { HandleError($"AES Key decryption failed: {ex.Message}"); }
            finally { DecryptAesKeyButton.IsEnabled = true; } // Re-enable button
        }

        // --- File Hash Verification Logic ---

        private async void CompareHashesButton_Click(object sender, RoutedEventArgs e)
        {
            string file1Path = HashFile1TextBox.Text;
            string file2Path = HashFile2TextBox.Text;

            // Clear previous results
            HashFile1ResultTextBox.Clear();
            HashFile2ResultTextBox.Clear();
            HashComparisonResultTextBlock.Text = "";
            HashComparisonResultTextBlock.Foreground = Brushes.Black; // Reset color

            // --- Input Validation ---
            if (string.IsNullOrWhiteSpace(file1Path) || string.IsNullOrWhiteSpace(file2Path))
            {
                UpdateStatus("Select two files to compare.");
                HashComparisonResultTextBlock.Text = "Please select both files.";
                HashComparisonResultTextBlock.Foreground = Brushes.OrangeRed;
                return;
            }
            if (!File.Exists(file1Path))
            {
                HandleError($"File not found: {file1Path}");
                HashFile1TextBox.Focus(); // Highlight the problem field
                return;
            }
            if (!File.Exists(file2Path))
            {
                HandleError($"File not found: {file2Path}");
                HashFile2TextBox.Focus(); // Highlight the problem field
                return;
            }

            UpdateStatus("Calculating hashes...");
            CompareHashesButton.IsEnabled = false;
            var stopwatch = Stopwatch.StartNew();

            try
            {
                // Calculate hashes concurrently
                string hash2 = CalculateFileHashAsync(file2Path);
                string hash1 = CalculateFileHashAsync(file1Path);

                stopwatch.Stop();
                UpdateStatus($"Hashes calculated in {stopwatch.ElapsedMilliseconds} ms.");

                // Display results
                HashFile1ResultTextBox.Text = hash1 ?? "Error calculating hash";
                HashFile2ResultTextBox.Text = hash2 ?? "Error calculating hash";

                // Compare and show result
                if (hash1 != null && hash2 != null)
                {
                    if (hash1.Equals(hash2, StringComparison.OrdinalIgnoreCase)) // Case-insensitive compare for hex
                    {
                        HashComparisonResultTextBlock.Text = "MATCH";
                        HashComparisonResultTextBlock.Foreground = Brushes.Green;
                    }
                    else
                    {
                        HashComparisonResultTextBlock.Text = "MISMATCH";
                        HashComparisonResultTextBlock.Foreground = Brushes.Red;
                    }
                }
                else
                {
                    HashComparisonResultTextBlock.Text = "Error: Could not compare hashes.";
                    HashComparisonResultTextBlock.Foreground = Brushes.OrangeRed;
                    // Specific error was already shown by HandleError in helper
                }
            }
            catch (Exception ex) // Catch errors during Task execution if helper didn't catch them
            {
                HandleError($"Error during hash comparison: {ex.Message}");
                HashComparisonResultTextBlock.Text = "Comparison Error";
                HashComparisonResultTextBlock.Foreground = Brushes.OrangeRed;
            }
            finally
            {
                CompareHashesButton.IsEnabled = true;
            }
        }

        // --- Helper Methods ---

        // New helper method to calculate SHA-256 hash of a file
        private string CalculateFileHashAsync(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                // Don't pop up a message box here, just return null. Let caller decide.
                UpdateStatus($"Hash Error: File not found '{filePath}'");
                return null;
            }

            try
            {
                using (var sha256 = SHA256.Create())
                {
                    // Use FileStream for async reading, especially important for large files
                    using (FileStream stream = File.OpenRead(filePath))
                    {
                        byte[] hashBytes = sha256.ComputeHash(stream);
                        // Convert byte array to a lowercase hexadecimal string
                        return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
                    }
                }
            }
            catch (IOException ioEx)
            {
                HandleError($"Error reading file for hashing '{Path.GetFileName(filePath)}': {ioEx.Message}");
                return null; // Return null on error
            }
            catch (UnauthorizedAccessException uaEx)
            {
                HandleError($"Permission error reading file for hashing '{Path.GetFileName(filePath)}': {uaEx.Message}");
                return null;
            }
            catch (Exception ex)
            {
                HandleError($"Error calculating hash for '{Path.GetFileName(filePath)}': {ex.Message}");
                return null;
            }
        }

        // Renamed original ValidateInput for clarity
        private bool ValidateKeyGenInput(string keyName, bool isRsa)
        {
            string keyType = isRsa ? "RSA" : "AES";
            if (!IsFolderValid(_defaultKeyFolder, "Please select a valid default key folder first.")) return false;
            if (string.IsNullOrWhiteSpace(keyName)) { HandleError($"Please enter a name for the {keyType} key."); return false; }
            if (HasInvalidFilenameChars(keyName)) { HandleError($"The key name '{keyName}' contains invalid characters."); return false; }
            return true;
        }

        // Simple check for invalid filename chars
        private bool HasInvalidFilenameChars(string filename)
        {
            return !string.IsNullOrWhiteSpace(filename) && filename.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0;
        }


        private bool IsFolderValid(string folderPath, string errorMessage = "Default folder not set or invalid.")
        {
            if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
            {
                // Only show error message if one was provided (avoids errors on startup)
                if (!string.IsNullOrEmpty(errorMessage))
                {
                    HandleError(errorMessage);
                }
                return false;
            }
            return true;
        }

        // Loads AES Key and IV from the specified file path.
        private (byte[] Key, byte[] IV) LoadAesKeyFromFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                HandleError($"AES Key file not found: {filePath}"); return (null, null);
            }
            try
            {
                string keyBase64 = null, ivBase64 = null;
                string[] lines = File.ReadAllLines(filePath);
                foreach (string line in lines)
                {
                    if (line.StartsWith("Key=", StringComparison.OrdinalIgnoreCase)) keyBase64 = line.Substring(4);
                    else if (line.StartsWith("IV=", StringComparison.OrdinalIgnoreCase)) ivBase64 = line.Substring(3);
                }

                if (string.IsNullOrEmpty(keyBase64) || string.IsNullOrEmpty(ivBase64))
                {
                    HandleError($"Invalid key file format: '{Path.GetFileName(filePath)}'. 'Key=' or 'IV=' missing/empty."); return (null, null);
                }

                return (Convert.FromBase64String(keyBase64), Convert.FromBase64String(ivBase64));
            }
            catch (FormatException ex) { HandleError($"Error parsing Base64 Key/IV from '{Path.GetFileName(filePath)}': {ex.Message}"); return (null, null); }
            catch (Exception ex) { HandleError($"Error reading AES key file '{Path.GetFileName(filePath)}': {ex.Message}"); return (null, null); }
        }

        // Helper to load RSA key from XML, optionally requiring private key
        private RSA LoadRsaKeyFromFile(string filePath, bool requirePrivateKey)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                HandleError($"RSA Key file not found: {filePath}"); return null;
            }
            try
            {
                string xmlString = File.ReadAllText(filePath);
                RSA rsa = new RSACng();
                rsa.FromXmlString(xmlString);

                // If private key is required, check if it loaded successfully
                if (requirePrivateKey)
                {
                    try
                    {
                        // Attempting to export private parameters will throw if they aren't present
                        _ = rsa.ExportParameters(true);
                    }
                    catch (CryptographicException)
                    {
                        HandleError($"Operation requires an RSA private key, but the selected file '{Path.GetFileName(filePath)}' does not contain one.");
                        rsa.Dispose(); // Dispose the object created
                        return null;
                    }
                }
                return rsa; // Success
            }
            catch (CryptographicException ex) { HandleError($"Error loading RSA key from '{Path.GetFileName(filePath)}'. Invalid XML format or key data? Details: {ex.Message}"); return null; }
            catch (Exception ex) { HandleError($"Error reading RSA key file '{Path.GetFileName(filePath)}': {ex.Message}"); return null; }
        }


        private void UpdateStatus(string message)
        { Dispatcher.Invoke(() => { StatusTextBlock.Text = message; }); }
        private void HandleError(string errorMessage)
        { Dispatcher.Invoke(() => { StatusTextBlock.Text = $"Error: {errorMessage}"; MessageBox.Show(errorMessage, "Error", MessageBoxButton.OK, MessageBoxImage.Error); }); }

    } // End class MainWindow


    // --- Data Classes (Unchanged) ---
    public class KeyInfo { public string Name { get; set; } public string Type { get; set; } public string FilePath { get; set; } }
    public class FileInfoSimple { public string Name { get; set; } public string FilePath { get; set; } }

} // End namespace
