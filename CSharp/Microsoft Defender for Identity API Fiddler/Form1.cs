using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Globalization;
using System.Text.RegularExpressions;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Xml.Linq;
using static System.Resources.ResXFileRef;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Security.Cryptography;

namespace Microsoft_Defender_for_Identity_API_Fiddler
{
    public partial class formFiddler : Form
    {
        public const int WM_NCLBUTTONDOWN = 0xA1;
        public const int HT_CAPTION = 0x2;

        [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
        public static extern int SendMessage(IntPtr hWnd, int Msg, int wParam, int lParam);
        [System.Runtime.InteropServices.DllImportAttribute("user32.dll")]
        public static extern bool ReleaseCapture();

        public formFiddler()
        {
            InitializeComponent();
            MoveSidePanel(btnDashboard);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Dashboard_512px;
            pnlDashboard.Visible = true;
            pnlRequest.Visible = false;
            pnlCompress.Visible = false;
            pnlDecompress.Visible = false;
            pnlSettings.Visible = false;
            pnlEncrypt.Visible = false;
            pnlDecrypt.Visible = false;
        }
        public static bool IsBase64String(string s)
        {
            s = s.Trim();
            return (s.Length % 4 == 0) && Regex.IsMatch(s, @"^[a-zA-Z0-9\+/]*={0,3}$", RegexOptions.None);
        }
        private void MoveSidePanel(Control c)
        {
            SidePanel.Height = c.Height;
            SidePanel.Top = c.Top;
        }

        private void btnExit_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void btnDashboard_Click(object sender, EventArgs e)
        {
            MoveSidePanel(btnDashboard);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Dashboard_512px;
            pnlDashboard.Visible = true;
            pnlRequest.Visible = false;
            pnlCompress.Visible = false;
            pnlDecompress.Visible = false;
            pnlSettings.Visible = false;
            pnlEncrypt.Visible = false;
            pnlDecrypt.Visible = false;
        }

        private void btnRequest_Click(object sender, EventArgs e)
        {
            MoveSidePanel(btnRequest);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Request_512px;
            pnlDashboard.Visible = false;
            pnlRequest.Visible = true;
            pnlCompress.Visible = false;
            pnlDecompress.Visible = false;
            pnlSettings.Visible = false;
            pnlEncrypt.Visible = false;
            pnlDecrypt.Visible = false;
        }

        private void btnCompress_Click(object sender, EventArgs e)
        {
            MoveSidePanel(btnCompress);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Compress_512px;
            pnlDashboard.Visible = false;
            pnlRequest.Visible = false;
            pnlCompress.Visible = true;
            pnlDecompress.Visible = false;
            pnlSettings.Visible = false;
            pnlEncrypt.Visible = false;
            pnlDecrypt.Visible = false;
        }

        private void btnDecompress_Click(object sender, EventArgs e)
        {
            MoveSidePanel(btnDecompress);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Decompress_512px;
            pnlDashboard.Visible = false;
            pnlRequest.Visible = false;
            pnlCompress.Visible = false;
            pnlDecompress.Visible = true;
            pnlSettings.Visible = false;
            pnlEncrypt.Visible = false;
            pnlDecrypt.Visible = false;
        }

        private void btnSettings_Click(object sender, EventArgs e)
        {
            MoveSidePanel(btnSettings);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Settings_512px;
            pnlDashboard.Visible = false;
            pnlRequest.Visible = false;
            pnlCompress.Visible = false;
            pnlDecompress.Visible = false;
            pnlSettings.Visible = true;
            pnlEncrypt.Visible = false;
            pnlDecrypt.Visible = false;
        }
        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            MoveSidePanel(btnEncrypt);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Encrypt_512px;
            pnlDashboard.Visible = false;
            pnlRequest.Visible = false;
            pnlCompress.Visible = false;
            pnlDecompress.Visible = false;
            pnlSettings.Visible = false;
            pnlEncrypt.Visible = true;
            pnlDecrypt.Visible = false;
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            MoveSidePanel(btnDecrypt);
            pbTitle.Image = Microsoft_Defender_for_Identity_API_Fiddler.Properties.Resources.Decrypt_512px;
            pnlDashboard.Visible = false;
            pnlRequest.Visible = false;
            pnlCompress.Visible = false;
            pnlDecompress.Visible = false;
            pnlSettings.Visible = false;
            pnlEncrypt.Visible = false;
            pnlDecrypt.Visible = true;
        }

        private void pnlTop_MouseDown(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Left)
            {
                ReleaseCapture();
                SendMessage(Handle, WM_NCLBUTTONDOWN, HT_CAPTION, 0);
            }
        }
        private static byte[] Compress(Stream input)
        {
            using (var compressStream = new MemoryStream())
            using (var compressor = new DeflateStream(compressStream, CompressionMode.Compress))
            {
                input.CopyTo(compressor);
                compressor.Close();
                return compressStream.ToArray();
            }
        }
        public static Stream Decompress(byte[] data)
        {
            var output = new MemoryStream();
            using (var compressedStream = new MemoryStream(data))
            using (var zipStream = new DeflateStream(compressedStream, CompressionMode.Decompress))
            {
                zipStream.CopyTo(output);
                zipStream.Close();
                output.Position = 0;
                return output;
            }
        }
        private void btnCompressCompress_Click(object sender, EventArgs e)
        {
            string value = richTxtBoxCompressDecompressed.Text;
            byte[] compressedBytes;

            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(value)))
            {
                compressedBytes = Compress(stream);
            }
            richTxtBoxCompressCompressed.Text = BitConverter.ToString(compressedBytes).Replace("-", ""); ;
        }

        public static byte[] ConvertHexStringToByteArray(string hexString)
        {
            byte[] data = new byte[hexString.Length / 2];
            for (int index = 0; index < data.Length; index++)
            {
                string byteValue = hexString.Substring(index * 2, 2);
                data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return data;
        }

        private void btnDecompressDecompress_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] compressedBytes = ConvertHexStringToByteArray(richTxtBoxDecompressCompressed.Text);
                using (var decompressedStream = Decompress(compressedBytes))
                using (var reader = new StreamReader(decompressedStream))
                {
                    string decompressedValue = reader.ReadToEnd();
                    richTxtBoxDecompressDecompressed.Text = decompressedValue;
                }
            }
            catch
            {
                richTxtBoxDecompressDecompressed.Text = "Can't decode bytes";
            }
        }

        private void btnRequestSend_Click(object sender, EventArgs e)
        {
            richTxtBoxRequestResponse.Clear();
            string value = richTxtBoxRequestBody.Text;
            string decompressedValue = "";
            byte[] compressedBytes;
            byte[] responseBytes;

            using (var stream = new MemoryStream(Encoding.UTF8.GetBytes(value)))
            {
                compressedBytes = Compress(stream);
            }


            MemoryStream stream1 = new MemoryStream(compressedBytes);
            StreamContent streamContent = new StreamContent(stream1);
            
            if (rbRequestJson.Checked == true)
            {
                var handler = new HttpClientHandler();
                handler.ClientCertificates.Add(new X509Certificate2(txtBoxCertificate.Text, txtBoxCertificatePassword.Text));
                var client = new HttpClient(handler);
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", txtBoxSettingsWorkspaceID.Text + ":" + txtBoxAccessKey.Text);
                var apiEndpoint = pnlRequestBody.Controls.OfType<RadioButton>().FirstOrDefault(r => r.Checked);
                string URI = "https://" + txtBoxSettingsWorkspaceName.Text + "sensorapi.atp.azure.com/api/" + apiEndpoint.Text + "/v1.0";
                using (var message = client.PostAsync(URI, streamContent).Result)
                {
                    string code = message.StatusCode.ToString();
                    richTxtBoxRequestResponse.Text = "Status: " + code + "\n";
                    responseBytes = message.Content.ReadAsByteArrayAsync().Result;

                    using (var decompressedStream = Decompress(responseBytes))
                    using (var reader = new StreamReader(decompressedStream))
                    {
                        decompressedValue = reader.ReadToEnd();
                    }
                    richTxtBoxRequestResponse.AppendText("Response: \n" + decompressedValue);
                }
            }
            
            else if (rbRequestSensorDeployment.Checked == true)
            {
                var client = new HttpClient();
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", txtBoxSettingsWorkspaceID.Text + ":" + txtBoxAccessKey.Text);
                var apiEndpoint = pnlRequestBody.Controls.OfType<RadioButton>().FirstOrDefault(r => r.Checked);
                string URI = "https://" + txtBoxSettingsWorkspaceName.Text + "sensorapi.atp.azure.com/api/" + apiEndpoint.Text + "/v1.0";
                using (var message = client.PostAsync(URI, streamContent).Result)
                {
                    string code = message.StatusCode.ToString();
                    richTxtBoxRequestResponse.Text = "Status: " + code + "\n";
                    responseBytes = message.Content.ReadAsByteArrayAsync().Result;

                    using (var decompressedStream = Decompress(responseBytes))
                    using (var reader = new StreamReader(decompressedStream))
                    {
                        decompressedValue = reader.ReadToEnd();
                    }
                    richTxtBoxRequestResponse.AppendText("Response: \n" + decompressedValue);
                }
            }            
        }
        private string EncryptPassword()
        {
            string EncryptedPassword = string.Empty;
            X509Certificate2 cert = new X509Certificate2(txtBoxCertificate.Text, txtBoxCertificatePassword.Text, X509KeyStorageFlags.MachineKeySet);
            using (RSA publicKey = cert.GetRSAPublicKey())
            {
                byte[] dataToEncrypt = Encoding.Unicode.GetBytes(richTextBoxEncryptDecrypted.Text);
                byte[] bytesDecrypted = publicKey.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
                EncryptedPassword = Convert.ToBase64String(bytesDecrypted);
            }
            return EncryptedPassword;
        }
        private string DecryptPassword()
        {
            string DecryptedPassword = string.Empty;
            X509Certificate2 cert = new X509Certificate2(txtBoxCertificate.Text, txtBoxCertificatePassword.Text, X509KeyStorageFlags.MachineKeySet);
            using (RSA privateKey = cert.GetRSAPrivateKey())
            {
                byte[] bytesEncrypted = Convert.FromBase64String(richTxtBoxDecryptEncrypted.Text);
                byte[] bytesDecrypted = privateKey.Decrypt(bytesEncrypted, RSAEncryptionPadding.OaepSHA256);
                DecryptedPassword = Encoding.Unicode.GetString(bytesDecrypted);
            }
            return DecryptedPassword;
        }
        private void btnDecryptDecrypt_Click(object sender, EventArgs e)
        {
            richTxtBoxDecryptDecrypted.Clear();
            richTxtBoxDecryptDecrypted.AppendText(DecryptPassword());
        }

        private void btnEncryptEncrypt_Click(object sender, EventArgs e)
        {
            richTextBoxEncryptEncrypted.Clear();
            richTextBoxEncryptEncrypted.AppendText(EncryptPassword());
        }
    }
}
