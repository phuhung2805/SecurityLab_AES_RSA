using System;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using SecurityLab_AES_RSA.Models;
using SecurityLab_AES_RSA.Services;

namespace SecurityLab_AES_RSA.UI
{
    public partial class MainForm : Form
    {
        private readonly AesCryptoService _aesService = new();
        private readonly RsaCryptoService _rsaService = new();
        private readonly PemParserService _pemService = new();
        private readonly HashAndSignatureService _hashService = new();

        // State hiện hành
        private AesKeyBundle? _currentAesKey;
        private RSA? _currentRsa;
        private CancellationTokenSource? _fileCts;

        public MainForm()
        {
            InitializeComponent();
            InitializeDefaultKeys();
        }

        private void InitializeDefaultKeys()
        {
            try
            {
                // Sinh mặc định khoá AES-256 và RSA-2048 khi khởi động để người dùng có thể thao tác ngay lập tức
                _currentAesKey = _aesService.GenerateKey(256);
                DisplayAesKeyInfo(_currentAesKey);

                _currentRsa = _rsaService.CreateRsaKey(2048);
                DisplayRsaKeyInfo(_currentRsa);
            }
            catch (Exception ex)
            {
                SetStatus($"Khởi tạo khoá mặc định: {ex.Message}", isError: true);
            }
        }

        private void SetStatus(string message, bool isError = false)
        {
            if (InvokeRequired)
            {
                Invoke(new Action(() => SetStatus(message, isError)));
                return;
            }
            lblStatus.Text = message;
            lblStatus.ForeColor = isError ? Color.DarkRed : Color.FromArgb(50, 60, 80);
        }

        #region TAB 1: MÃ HOÁ ĐỐI XỨNG AES (UI & LOGIC)

        private ComboBox cboAesKeySize = null!;
        private TextBox txtAesKeyBase64 = null!;
        private TextBox txtAesKeyHex = null!;
        private TextBox txtAesIvBase64 = null!;
        private TextBox txtAesIvHex = null!;

        private TextBox txtAesPlainText = null!;
        private TextBox txtAesCipherText = null!;

        private ComboBox cboDummySize = null!;
        private TextBox txtAesFileSource = null!;
        private TextBox txtAesFileEncrypted = null!;
        private TextBox txtAesFileDecrypted = null!;
        private ProgressBar prgAesFile = null!;
        private Label lblAesFileProgress = null!;
        private TextBox txtAesFileResult = null!;
        private Button btnCancelAesFile = null!;

        private void InitializeTabAes()
        {
            tabAes.AutoScroll = true;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                AutoScroll = true,
                Padding = new Padding(12)
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            // ================= 1. Quản lý khoá AES =================
            var grpKey = new GroupBox
            {
                Text = "1. Quản lý Khoá AES & Vector Khởi tạo (IV)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(12),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var flpKeyControls = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                WrapContents = true
            };

            var lblKeySize = new Label { Text = "Độ dài khoá:", AutoSize = true, Anchor = AnchorStyles.Left };
            cboAesKeySize = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
            cboAesKeySize.Items.AddRange(new object[] { "128-bit", "192-bit", "256-bit" });
            cboAesKeySize.SelectedIndex = 2; // 256-bit mặc định

            var btnGenKey = new Button { Text = "Sinh khoá AES", Width = 130, Height = 28, BackColor = Color.FromArgb(235, 243, 255) };
            btnGenKey.Click += BtnGenKey_Click;

            var btnExportKey = new Button { Text = "Lưu khoá ra file (.aeskey)", Width = 180, Height = 28 };
            btnExportKey.Click += BtnExportKey_Click;

            var btnImportKey = new Button { Text = "Import khoá từ file...", Width = 160, Height = 28 };
            btnImportKey.Click += BtnImportKey_Click;

            flpKeyControls.Controls.AddRange(new Control[] { lblKeySize, cboAesKeySize, btnGenKey, btnExportKey, btnImportKey });

            var tlpKeyDisplay = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 4,
                RowCount = 2,
                AutoSize = true,
                Padding = new Padding(0, 8, 0, 0)
            };
            tlpKeyDisplay.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
            tlpKeyDisplay.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            tlpKeyDisplay.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
            tlpKeyDisplay.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            txtAesKeyBase64 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };
            txtAesKeyHex = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };
            txtAesIvBase64 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };
            txtAesIvHex = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };

            tlpKeyDisplay.Controls.Add(new Label { Text = "Key (Base64):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpKeyDisplay.Controls.Add(txtAesKeyBase64, 1, 0);
            tlpKeyDisplay.Controls.Add(new Label { Text = "Key (Hex):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 2, 0);
            tlpKeyDisplay.Controls.Add(txtAesKeyHex, 3, 0);

            tlpKeyDisplay.Controls.Add(new Label { Text = "IV (Base64):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 1);
            tlpKeyDisplay.Controls.Add(txtAesIvBase64, 1, 1);
            tlpKeyDisplay.Controls.Add(new Label { Text = "IV (Hex - 16 bytes):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 2, 1);
            tlpKeyDisplay.Controls.Add(txtAesIvHex, 3, 1);

            grpKey.Controls.Add(tlpKeyDisplay);
            grpKey.Controls.Add(flpKeyControls);

            // ================= 2. Mã hoá / Giải mã Văn bản =================
            var grpText = new GroupBox
            {
                Text = "2. Mã hoá / Giải mã Văn bản (AES-CBC-PKCS7)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(12),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tlpText = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 3,
                RowCount = 2,
                Height = 120
            };
            tlpText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 45));
            tlpText.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
            tlpText.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 55));

            txtAesPlainText = new TextBox
            {
                Multiline = true,
                Dock = DockStyle.Fill,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Segoe UI", 9F),
                Text = "Khoa Công nghệ Thông tin - Môn học An toàn và Bảo mật thông tin. Thực hành giải thuật AES-256 đối xứng."
            };

            var pnlTextButtons = new Panel { Dock = DockStyle.Fill };
            var btnEncryptText = new Button
            {
                Text = "Mã hoá Text ➔",
                Width = 145,
                Height = 32,
                Location = new Point(8, 15),
                BackColor = Color.FromArgb(230, 245, 230)
            };
            btnEncryptText.Click += BtnEncryptText_Click;

            var btnDecryptText = new Button
            {
                Text = "⬅ Giải mã Text",
                Width = 145,
                Height = 32,
                Location = new Point(8, 55),
                BackColor = Color.FromArgb(245, 240, 230)
            };
            btnDecryptText.Click += BtnDecryptText_Click;

            pnlTextButtons.Controls.Add(btnEncryptText);
            pnlTextButtons.Controls.Add(btnDecryptText);

            txtAesCipherText = new TextBox
            {
                Multiline = true,
                Dock = DockStyle.Fill,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.5F)
            };

            tlpText.Controls.Add(new Label { Text = "Văn bản gốc (Plaintext):", Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpText.Controls.Add(new Label(), 1, 0);
            tlpText.Controls.Add(new Label { Text = "Bản mã (Ciphertext Base64):", Font = new Font("Segoe UI", 9F) }, 2, 0);

            tlpText.Controls.Add(txtAesPlainText, 0, 1);
            tlpText.Controls.Add(pnlTextButtons, 1, 1);
            tlpText.Controls.Add(txtAesCipherText, 2, 1);

            grpText.Controls.Add(tlpText);

            // ================= 3. Mã hoá / Giải mã File lớn =================
            var grpFile = new GroupBox
            {
                Text = "3. Mã hoá / Giải mã File kích thước lớn (Hàng GB) & Thử nghiệm hiệu năng (Streaming Buffer 1MB)",
                Dock = DockStyle.Fill,
                Padding = new Padding(12),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var pnlFileTop = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                WrapContents = true,
                Padding = new Padding(0, 0, 0, 8)
            };

            pnlFileTop.Controls.Add(new Label { Text = "Tiện ích tạo file mẫu lớn (Dummy File):", AutoSize = true, Anchor = AnchorStyles.Left });
            cboDummySize = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
            cboDummySize.Items.AddRange(new object[] { "100 MB", "500 MB", "1 GB", "2 GB" });
            cboDummySize.SelectedIndex = 0;
            pnlFileTop.Controls.Add(cboDummySize);

            var btnCreateDummy = new Button { Text = "Tạo file mẫu lớn (Dummy)", Width = 180, Height = 28, BackColor = Color.FromArgb(240, 245, 255) };
            btnCreateDummy.Click += BtnCreateDummy_Click;
            pnlFileTop.Controls.Add(btnCreateDummy);

            var tlpFilePaths = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 3,
                RowCount = 3,
                Height = 95
            };
            tlpFilePaths.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
            tlpFilePaths.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tlpFilePaths.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));

            txtAesFileSource = new TextBox { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9F) };
            txtAesFileEncrypted = new TextBox { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9F) };
            txtAesFileDecrypted = new TextBox { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9F) };

            var btnBrowseSource = new Button { Text = "Chọn file...", Dock = DockStyle.Fill };
            btnBrowseSource.Click += (s, e) => BrowseFile(txtAesFileSource, isSave: false);

            var btnBrowseEnc = new Button { Text = "Chọn file...", Dock = DockStyle.Fill };
            btnBrowseEnc.Click += (s, e) => BrowseFile(txtAesFileEncrypted, isSave: false);

            var btnBrowseDec = new Button { Text = "Chọn file...", Dock = DockStyle.Fill };
            btnBrowseDec.Click += (s, e) => BrowseFile(txtAesFileDecrypted, isSave: false);

            tlpFilePaths.Controls.Add(new Label { Text = "File nguồn:", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpFilePaths.Controls.Add(txtAesFileSource, 1, 0);
            tlpFilePaths.Controls.Add(btnBrowseSource, 2, 0);

            tlpFilePaths.Controls.Add(new Label { Text = "File mã hoá (.aes):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 1);
            tlpFilePaths.Controls.Add(txtAesFileEncrypted, 1, 1);
            tlpFilePaths.Controls.Add(btnBrowseEnc, 2, 1);

            tlpFilePaths.Controls.Add(new Label { Text = "File giải mã:", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 2);
            tlpFilePaths.Controls.Add(txtAesFileDecrypted, 1, 2);
            tlpFilePaths.Controls.Add(btnBrowseDec, 2, 2);

            var flpFileActions = new FlowLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(0, 8, 0, 8)
            };

            var btnEncryptFile = new Button { Text = "Bắt đầu Mã hoá File (AES-CBC)", Width = 210, Height = 32, BackColor = Color.FromArgb(230, 245, 230) };
            btnEncryptFile.Click += BtnEncryptFile_Click;

            var btnDecryptFile = new Button { Text = "Bắt đầu Giải mã File", Width = 180, Height = 32, BackColor = Color.FromArgb(245, 240, 230) };
            btnDecryptFile.Click += BtnDecryptFile_Click;

            var btnCompareBytes = new Button { Text = "So sánh theo từng Byte (Compare Bytes)", Width = 270, Height = 32, BackColor = Color.FromArgb(240, 240, 255) };
            btnCompareBytes.Click += BtnCompareBytes_Click;

            btnCancelAesFile = new Button { Text = "Hủy tác vụ", Width = 110, Height = 32, Enabled = false, ForeColor = Color.DarkRed };
            btnCancelAesFile.Click += (s, e) => _fileCts?.Cancel();

            flpFileActions.Controls.AddRange(new Control[] { btnEncryptFile, btnDecryptFile, btnCompareBytes, btnCancelAesFile });

            prgAesFile = new ProgressBar { Dock = DockStyle.Top, Height = 20 };
            lblAesFileProgress = new Label
            {
                Dock = DockStyle.Top,
                Text = "Tiến độ: 0% | Tốc độ: 0 MB/s | Thời gian: 0s",
                Font = new Font("Segoe UI", 9F, FontStyle.Italic),
                ForeColor = Color.DimGray,
                Height = 22
            };

            txtAesFileResult = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9F),
                BackColor = Color.FromArgb(250, 252, 255)
            };

            grpFile.Controls.Add(txtAesFileResult);
            grpFile.Controls.Add(lblAesFileProgress);
            grpFile.Controls.Add(prgAesFile);
            grpFile.Controls.Add(flpFileActions);
            grpFile.Controls.Add(tlpFilePaths);
            grpFile.Controls.Add(pnlFileTop);

            mainLayout.Controls.Add(grpKey, 0, 0);
            mainLayout.Controls.Add(grpText, 0, 1);
            mainLayout.Controls.Add(grpFile, 0, 2);

            tabAes.Controls.Add(mainLayout);
        }

        private void DisplayAesKeyInfo(AesKeyBundle bundle)
        {
            txtAesKeyBase64.Text = bundle.KeyBase64;
            txtAesKeyHex.Text = bundle.KeyHex;
            txtAesIvBase64.Text = bundle.IvBase64;
            txtAesIvHex.Text = bundle.IvHex;
            SetStatus($"Đã nạp khoá AES-{bundle.KeySizeBits} và IV 128-bit thành công.");
        }

        private void BtnGenKey_Click(object? sender, EventArgs e)
        {
            int bits = cboAesKeySize.SelectedIndex switch
            {
                0 => 128,
                1 => 192,
                _ => 256
            };
            _currentAesKey = _aesService.GenerateKey(bits);
            DisplayAesKeyInfo(_currentAesKey);
        }

        private async void BtnExportKey_Click(object? sender, EventArgs e)
        {
            if (_currentAesKey == null) return;
            using var sfd = new SaveFileDialog
            {
                Filter = "AES Key File (*.aeskey)|*.aeskey",
                FileName = $"aes_{_currentAesKey.KeySizeBits}_{DateTime.Now:yyyyMMdd_HHmmss}.aeskey"
            };
            if (sfd.ShowDialog() == DialogResult.OK)
            {
                await _aesService.ExportKeyToFileAsync(_currentAesKey, sfd.FileName);
                MessageBox.Show($"Đã lưu khoá AES ra file:\n{sfd.FileName}", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private async void BtnImportKey_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog { Filter = "AES Key File (*.aeskey)|*.aeskey" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    _currentAesKey = await _aesService.ImportKeyFromFileAsync(ofd.FileName);
                    DisplayAesKeyInfo(_currentAesKey);
                    MessageBox.Show("Nạp khoá AES từ file thành công!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Lỗi import khoá: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void BtnEncryptText_Click(object? sender, EventArgs e)
        {
            if (_currentAesKey == null)
            {
                MessageBox.Show("Vui lòng sinh hoặc nạp khoá AES trước.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try
            {
                txtAesCipherText.Text = _aesService.EncryptText(txtAesPlainText.Text, _currentAesKey.GetKeyBytes(), _currentAesKey.GetIvBytes());
                SetStatus("Mã hoá văn bản AES hoàn tất.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi mã hoá văn bản: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnDecryptText_Click(object? sender, EventArgs e)
        {
            if (_currentAesKey == null)
            {
                MessageBox.Show("Vui lòng sinh hoặc nạp khoá AES trước.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try
            {
                txtAesPlainText.Text = _aesService.DecryptText(txtAesCipherText.Text.Trim(), _currentAesKey.GetKeyBytes(), _currentAesKey.GetIvBytes());
                SetStatus("Giải mã văn bản AES hoàn tất.");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi giải mã văn bản: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private async void BtnCreateDummy_Click(object? sender, EventArgs e)
        {
            long sizeBytes = cboDummySize.SelectedIndex switch
            {
                0 => 100L * 1024 * 1024,
                1 => 500L * 1024 * 1024,
                2 => 1024L * 1024 * 1024,
                3 => 2048L * 1024 * 1024,
                _ => 100L * 1024 * 1024
            };

            using var sfd = new SaveFileDialog
            {
                Filter = "Binary Data (*.bin;*.dat)|*.bin;*.dat",
                FileName = $"sample_dummy_{cboDummySize.SelectedItem?.ToString()?.Replace(" ", "")}.bin"
            };
            if (sfd.ShowDialog() != DialogResult.OK) return;

            string targetPath = sfd.FileName;
            _fileCts = new CancellationTokenSource();
            btnCancelAesFile.Enabled = true;

            var progress = new Progress<(long written, long total, double percent)>(p =>
            {
                prgAesFile.Value = Math.Clamp((int)p.percent, 0, 100);
                lblAesFileProgress.Text = $"Đang tạo Dummy File: {p.written / (1024.0 * 1024.0):F1} MB / {p.total / (1024.0 * 1024.0):F1} MB ({p.percent:F1}%)";
            });

            try
            {
                txtAesFileResult.AppendText($"[TẠO FILE MẪU] Bắt đầu sinh file {sizeBytes / (1024.0 * 1024.0):N0} MB...\r\n");
                await _aesService.GenerateDummyFileAsync(targetPath, sizeBytes, progress, _fileCts.Token);
                txtAesFileSource.Text = targetPath;
                txtAesFileEncrypted.Text = targetPath + ".aes";
                txtAesFileDecrypted.Text = targetPath + ".decrypted.bin";
                txtAesFileResult.AppendText($"[TẠO FILE MẪU] Hoàn tất: {targetPath}\r\n\r\n");
                MessageBox.Show("Tạo dummy file mẫu lớn thành công!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (OperationCanceledException)
            {
                txtAesFileResult.AppendText("[TẠO FILE MẪU] Tác vụ đã bị người dùng hủy.\r\n");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi tạo file: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnCancelAesFile.Enabled = false;
                prgAesFile.Value = 0;
            }
        }

        private async void BtnEncryptFile_Click(object? sender, EventArgs e)
        {
            if (_currentAesKey == null)
            {
                MessageBox.Show("Vui lòng sinh hoặc nạp khoá AES trước.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (!File.Exists(txtAesFileSource.Text))
            {
                MessageBox.Show("Vui lòng chọn file nguồn hợp lệ.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string sourcePath = txtAesFileSource.Text;
            string outPath = string.IsNullOrWhiteSpace(txtAesFileEncrypted.Text) ? sourcePath + ".aes" : txtAesFileEncrypted.Text;
            txtAesFileEncrypted.Text = outPath;

            _fileCts = new CancellationTokenSource();
            btnCancelAesFile.Enabled = true;

            var progress = new Progress<(long processed, long total, double speedMbPerSec)>(p =>
            {
                int pct = p.total > 0 ? (int)((double)p.processed / p.total * 100) : 0;
                prgAesFile.Value = Math.Clamp(pct, 0, 100);
                lblAesFileProgress.Text = $"Mã hoá: {p.processed / (1024.0 * 1024.0):F1} MB / {p.total / (1024.0 * 1024.0):F1} MB ({pct}%) | Tốc độ: {p.speedMbPerSec:F2} MB/s";
            });

            try
            {
                txtAesFileResult.AppendText($"=== BẮT ĐẦU MÃ HOÁ FILE: {Path.GetFileName(sourcePath)} ===\r\n");
                var result = await _aesService.EncryptFileAsync(sourcePath, outPath, _currentAesKey.GetKeyBytes(), _currentAesKey.GetIvBytes(), progress, _fileCts.Token);
                
                txtAesFileResult.AppendText($"✓ Mã hoá thành công: {result.FilePath}\r\n");
                txtAesFileResult.AppendText($"  • Dung lượng: {result.FileSizeBytes:N0} bytes ({result.FileSizeBytes / (1024.0 * 1024.0):F2} MB)\r\n");
                txtAesFileResult.AppendText($"  • Thời gian: {result.Elapsed.TotalSeconds:F2} giây ({result.Elapsed.TotalMilliseconds:F1} ms)\r\n");
                txtAesFileResult.AppendText($"  • Tốc độ trung bình: {result.SpeedMBps:F2} MB/s\r\n");
                txtAesFileResult.AppendText($"  • SHA-256 file mã hoá: {result.Sha256Hash}\r\n\r\n");

                if (string.IsNullOrWhiteSpace(txtAesFileDecrypted.Text))
                {
                    txtAesFileDecrypted.Text = sourcePath + ".decrypted" + Path.GetExtension(sourcePath);
                }
            }
            catch (OperationCanceledException)
            {
                txtAesFileResult.AppendText("[MÃ HOÁ FILE] Đã dừng tác vụ theo yêu cầu người dùng.\r\n");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi mã hoá file: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnCancelAesFile.Enabled = false;
                prgAesFile.Value = 0;
            }
        }

        private async void BtnDecryptFile_Click(object? sender, EventArgs e)
        {
            if (_currentAesKey == null)
            {
                MessageBox.Show("Vui lòng sinh hoặc nạp khoá AES trước.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            if (!File.Exists(txtAesFileEncrypted.Text))
            {
                MessageBox.Show("Vui lòng chọn file mã hoá (.aes) hợp lệ.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            string encPath = txtAesFileEncrypted.Text;
            string outPath = string.IsNullOrWhiteSpace(txtAesFileDecrypted.Text) ? encPath + ".decrypted.bin" : txtAesFileDecrypted.Text;
            txtAesFileDecrypted.Text = outPath;

            _fileCts = new CancellationTokenSource();
            btnCancelAesFile.Enabled = true;

            var progress = new Progress<(long processed, long total, double speedMbPerSec)>(p =>
            {
                int pct = p.total > 0 ? (int)((double)p.processed / p.total * 100) : 0;
                prgAesFile.Value = Math.Clamp(pct, 0, 100);
                lblAesFileProgress.Text = $"Giải mã: {p.processed / (1024.0 * 1024.0):F1} MB / {p.total / (1024.0 * 1024.0):F1} MB ({pct}%) | Tốc độ: {p.speedMbPerSec:F2} MB/s";
            });

            try
            {
                txtAesFileResult.AppendText($"=== BẮT ĐẦU GIẢI MÃ FILE: {Path.GetFileName(encPath)} ===\r\n");
                var result = await _aesService.DecryptFileAsync(encPath, outPath, _currentAesKey.GetKeyBytes(), _currentAesKey.GetIvBytes(), progress, _fileCts.Token);

                txtAesFileResult.AppendText($"✓ Giải mã thành công: {result.FilePath}\r\n");
                txtAesFileResult.AppendText($"  • Dung lượng: {result.FileSizeBytes:N0} bytes ({result.FileSizeBytes / (1024.0 * 1024.0):F2} MB)\r\n");
                txtAesFileResult.AppendText($"  • Thời gian: {result.Elapsed.TotalSeconds:F2} giây ({result.Elapsed.TotalMilliseconds:F1} ms)\r\n");
                txtAesFileResult.AppendText($"  • Tốc độ trung bình: {result.SpeedMBps:F2} MB/s\r\n");
                txtAesFileResult.AppendText($"  • SHA-256 file giải mã: {result.Sha256Hash}\r\n\r\n");
            }
            catch (OperationCanceledException)
            {
                txtAesFileResult.AppendText("[GIẢI MÃ FILE] Đã dừng tác vụ theo yêu cầu người dùng.\r\n");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi giải mã file: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnCancelAesFile.Enabled = false;
                prgAesFile.Value = 0;
            }
        }

        private async void BtnCompareBytes_Click(object? sender, EventArgs e)
        {
            if (!File.Exists(txtAesFileSource.Text) || !File.Exists(txtAesFileDecrypted.Text))
            {
                MessageBox.Show("Vui lòng chỉ định đúng đường dẫn File nguồn và File sau giải mã.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            _fileCts = new CancellationTokenSource();
            btnCancelAesFile.Enabled = true;

            var progress = new Progress<(long compared, long total)>(p =>
            {
                int pct = p.total > 0 ? (int)((double)p.compared / p.total * 100) : 0;
                prgAesFile.Value = Math.Clamp(pct, 0, 100);
                lblAesFileProgress.Text = $"Đang so sánh: {p.compared / (1024.0 * 1024.0):F1} MB / {p.total / (1024.0 * 1024.0):F1} MB ({pct}%)";
            });

            try
            {
                txtAesFileResult.AppendText("=== ĐỐI CHIẾU FILE NGUỒN VS FILE GIẢI MÃ (STREAMING BYTE-BY-BYTE) ===\r\n");
                var cmp = await _aesService.CompareFilesAsync(txtAesFileSource.Text, txtAesFileDecrypted.Text, progress, _fileCts.Token);

                txtAesFileResult.AppendText($"  • File nguồn SHA-256:   {cmp.Sha256Source}\r\n");
                txtAesFileResult.AppendText($"  • File giải mã SHA-256: {cmp.Sha256Decrypted}\r\n");
                txtAesFileResult.AppendText($"  • Tổng số byte kiểm tra: {cmp.TotalBytesCompared:N0} bytes\r\n");
                txtAesFileResult.AppendText($"  • Số byte sai khác:     {cmp.MismatchCount} bytes\r\n");
                txtAesFileResult.AppendText($"  • Thời gian đối chiếu:  {cmp.Elapsed.TotalSeconds:F2} giây\r\n");
                txtAesFileResult.AppendText($"  • KẾT LUẬN: {cmp.Conclusion}\r\n\r\n");

                MessageBox.Show(cmp.Conclusion, cmp.AreIdentical ? "Khớp 100%" : "Có sai khác", MessageBoxButtons.OK,
                    cmp.AreIdentical ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
            }
            catch (OperationCanceledException)
            {
                txtAesFileResult.AppendText("[SO SÁNH FILE] Tác vụ đã bị người dùng hủy.\r\n");
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi so sánh file: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnCancelAesFile.Enabled = false;
                prgAesFile.Value = 0;
            }
        }

        private static void BrowseFile(TextBox target, bool isSave)
        {
            if (isSave)
            {
                using var sfd = new SaveFileDialog();
                if (sfd.ShowDialog() == DialogResult.OK) target.Text = sfd.FileName;
            }
            else
            {
                using var ofd = new OpenFileDialog();
                if (ofd.ShowDialog() == DialogResult.OK) target.Text = ofd.FileName;
            }
        }

        #endregion

        #region TAB 2: MÃ HOÁ BẤT ĐỐI XỨNG RSA & PHÂN TÍCH PEM (UI & LOGIC)

        private ComboBox cboRsaKeySize = null!;
        private TextBox txtPemRaw = null!;
        private TextBox txtPemHexDump = null!;
        private DataGridView dgvAsn1 = null!;

        private TextBox txtRsaModulus = null!;
        private TextBox txtRsaExponent = null!;
        private TextBox txtRsaPrivateParams = null!;

        private TextBox txtRsaDataInput = null!;
        private TextBox txtRsaCipherBase64 = null!;
        private Label lblRsaVerifyResult = null!;

        private NumericUpDown numBenchIterations = null!;
        private Label lblBenchPublicResult = null!;
        private Label lblBenchPrivateResult = null!;
        private Label lblBenchRatio = null!;
        private TextBox txtBenchExplanation = null!;

        private void InitializeTabRsa()
        {
            tabRsa.AutoScroll = true;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                AutoScroll = true,
                Padding = new Padding(12)
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 280));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            // ================= 1. Sinh & Xuất cặp khoá RSA =================
            var grpKey = new GroupBox
            {
                Text = "1. Sinh & Xuất cặp khoá RSA (2048 / 4096-bit)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var flpKey = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true };
            flpKey.Controls.Add(new Label { Text = "Độ dài khoá:", Anchor = AnchorStyles.Left, AutoSize = true });

            cboRsaKeySize = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList, Width = 110 };
            cboRsaKeySize.Items.AddRange(new object[] { "2048-bit", "4096-bit" });
            cboRsaKeySize.SelectedIndex = 0;
            flpKey.Controls.Add(cboRsaKeySize);

            var btnGenRsa = new Button { Text = "Sinh cặp khoá RSA", Width = 150, Height = 28, BackColor = Color.FromArgb(235, 243, 255) };
            btnGenRsa.Click += BtnGenRsa_Click;

            var btnExportPub = new Button { Text = "Xuất Public Key (.pem)", Width = 170, Height = 28 };
            btnExportPub.Click += BtnExportPub_Click;

            var btnExportPriv = new Button { Text = "Xuất Private Key (.pem)", Width = 175, Height = 28 };
            btnExportPriv.Click += BtnExportPriv_Click;

            var btnImportPub = new Button { Text = "Nhập Public Key (.pem)...", Width = 185, Height = 28 };
            btnImportPub.Click += BtnImportPub_Click;

            var btnImportPriv = new Button { Text = "Nhập Private Key (.pem)...", Width = 190, Height = 28 };
            btnImportPriv.Click += BtnImportPriv_Click;

            flpKey.Controls.AddRange(new Control[] { btnGenRsa, btnExportPub, btnExportPriv, btnImportPub, btnImportPriv });
            grpKey.Controls.Add(flpKey);

            // ================= 2. View PEM & ASN.1 DER Breakdown =================
            var grpPem = new GroupBox
            {
                Text = "2. Phân tích cấu trúc PEM & Bóc tách cây ASN.1 DER (TLV Breakdown)",
                Dock = DockStyle.Fill,
                Padding = new Padding(8),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tabPemDetails = new TabControl { Dock = DockStyle.Fill, Font = new Font("Segoe UI", 9F) };
            var tabSubRaw = new TabPage("Văn bản PEM (Header + Base64 + Footer)");
            var tabSubHex = new TabPage("Hex Dump nhị phân DER");
            var tabSubTlv = new TabPage("Cấu trúc ASN.1 DER (Tag, Length, Value, Tên trường)");

            txtPemRaw = new TextBox { Multiline = true, Dock = DockStyle.Fill, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 8.5F) };
            tabSubRaw.Controls.Add(txtPemRaw);

            txtPemHexDump = new TextBox { Multiline = true, Dock = DockStyle.Fill, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 8F) };
            tabSubHex.Controls.Add(txtPemHexDump);

            dgvAsn1 = new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AllowUserToAddRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                Font = new Font("Segoe UI", 8.5F)
            };
            dgvAsn1.Columns.Add("colOffset", "Offset");
            dgvAsn1.Columns.Add("colTag", "Tag");
            dgvAsn1.Columns.Add("colType", "Loại thẻ ASN.1");
            dgvAsn1.Columns.Add("colLen", "Độ dài");
            dgvAsn1.Columns.Add("colField", "Tên trường toán học");
            dgvAsn1.Columns.Add("colVal", "Giá trị tóm tắt");
            dgvAsn1.Columns.Add("colExpl", "Ý nghĩa cấu trúc");
            dgvAsn1.Columns["colOffset"].FillWeight = 10;
            dgvAsn1.Columns["colTag"].FillWeight = 10;
            dgvAsn1.Columns["colType"].FillWeight = 18;
            dgvAsn1.Columns["colLen"].FillWeight = 10;
            dgvAsn1.Columns["colField"].FillWeight = 26;
            dgvAsn1.Columns["colVal"].FillWeight = 26;
            dgvAsn1.Columns["colExpl"].FillWeight = 45;
            tabSubTlv.Controls.Add(dgvAsn1);

            tabPemDetails.TabPages.AddRange(new[] { tabSubTlv, tabSubRaw, tabSubHex });
            grpPem.Controls.Add(tabPemDetails);

            // ================= 3. Tham số toán học =================
            var grpParams = new GroupBox
            {
                Text = "3. Tham số toán học trích xuất từ khoá (n, e, d, p, q, dp, dq, qInv)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tlpParams = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 2,
                RowCount = 3,
                AutoSize = true
            };
            tlpParams.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            tlpParams.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            txtRsaModulus = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };
            txtRsaExponent = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };
            txtRsaPrivateParams = new TextBox { Dock = DockStyle.Fill, Multiline = true, Height = 60, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Font = new Font("Consolas", 8.5F) };

            tlpParams.Controls.Add(new Label { Text = "Modulus n (Hex):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpParams.Controls.Add(txtRsaModulus, 1, 0);

            tlpParams.Controls.Add(new Label { Text = "Public Exponent e:", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 1);
            tlpParams.Controls.Add(txtRsaExponent, 1, 1);

            tlpParams.Controls.Add(new Label { Text = "Private Key Params (d, p, q):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 2);
            tlpParams.Controls.Add(txtRsaPrivateParams, 1, 2);

            grpParams.Controls.Add(tlpParams);

            // ================= 4. Mã hoá / Giải mã <= 190 bytes =================
            var grpData = new GroupBox
            {
                Text = "4. Mã hoá & Giải mã dữ liệu <= 190 bytes (RSA-2048 OAEP-SHA256)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tlpData = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 3,
                RowCount = 3,
                AutoSize = true
            };
            tlpData.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            tlpData.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tlpData.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 220));

            txtRsaDataInput = new TextBox
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 9F),
                Text = "Khoá bí mật AES-256 đối xứng cần bảo vệ qua phong bì số RSA."
            };

            var btnUseAesKey = new Button { Text = "Lấy khoá AES-256 (32 bytes)", Dock = DockStyle.Fill, BackColor = Color.FromArgb(240, 245, 255) };
            btnUseAesKey.Click += (s, e) =>
            {
                if (_currentAesKey != null) txtRsaDataInput.Text = _currentAesKey.KeyBase64;
            };

            txtRsaCipherBase64 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };

            var btnEncryptData = new Button { Text = "Mã hoá RSA ➔ Lưu .enc", Dock = DockStyle.Fill, BackColor = Color.FromArgb(230, 245, 230) };
            btnEncryptData.Click += BtnEncryptRsaData_Click;

            var btnDecryptData = new Button { Text = "Giải mã file .enc ➔ Đối chiếu", Dock = DockStyle.Fill, BackColor = Color.FromArgb(245, 240, 230) };
            btnDecryptData.Click += BtnDecryptRsaData_Click;

            lblRsaVerifyResult = new Label
            {
                Text = "Chưa thực hiện đối chiếu giải mã.",
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 9F, FontStyle.Italic),
                ForeColor = Color.DimGray
            };

            tlpData.Controls.Add(new Label { Text = "Dữ liệu vào (<= 190 bytes):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpData.Controls.Add(txtRsaDataInput, 1, 0);
            tlpData.Controls.Add(btnUseAesKey, 2, 0);

            tlpData.Controls.Add(new Label { Text = "Bản mã RSA (Base64):", Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 9F) }, 0, 1);
            tlpData.Controls.Add(txtRsaCipherBase64, 1, 1);
            tlpData.Controls.Add(btnEncryptData, 2, 1);

            tlpData.Controls.Add(lblRsaVerifyResult, 1, 2);
            tlpData.Controls.Add(btnDecryptData, 2, 2);

            grpData.Controls.Add(tlpData);

            // ================= 5. Benchmark Tốc độ =================
            var grpBench = new GroupBox
            {
                Text = "5. Đánh giá tốc độ Mã hoá (Public Key) vs Giải mã (Private Key) theo cơ chế toán học",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var flpBenchTop = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
            flpBenchTop.Controls.Add(new Label { Text = "Số lần lặp thử nghiệm:", Anchor = AnchorStyles.Left, AutoSize = true });

            numBenchIterations = new NumericUpDown { Minimum = 50, Maximum = 5000, Value = 500, Increment = 50, Width = 80 };
            flpBenchTop.Controls.Add(numBenchIterations);

            var btnRunBench = new Button { Text = "Chạy Benchmark so sánh tốc độ", Width = 230, Height = 28, BackColor = Color.FromArgb(235, 245, 255) };
            btnRunBench.Click += BtnRunRsaBench_Click;
            flpBenchTop.Controls.Add(btnRunBench);

            lblBenchPublicResult = new Label { Text = "Public Key: Chưa đo", AutoSize = true, Margin = new Padding(15, 6, 0, 0) };
            lblBenchPrivateResult = new Label { Text = "Private Key: Chưa đo", AutoSize = true, Margin = new Padding(15, 6, 0, 0) };
            lblBenchRatio = new Label { Text = "Tỷ lệ chênh lệch: N/A", AutoSize = true, Font = new Font("Segoe UI", 9F, FontStyle.Bold), ForeColor = Color.DarkBlue, Margin = new Padding(15, 6, 0, 0) };

            flpBenchTop.Controls.AddRange(new Control[] { lblBenchPublicResult, lblBenchPrivateResult, lblBenchRatio });

            txtBenchExplanation = new TextBox
            {
                Dock = DockStyle.Top,
                Multiline = true,
                Height = 85,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Segoe UI", 9F),
                BackColor = Color.FromArgb(250, 252, 255)
            };

            grpBench.Controls.Add(txtBenchExplanation);
            grpBench.Controls.Add(flpBenchTop);

            mainLayout.Controls.Add(grpKey, 0, 0);
            mainLayout.Controls.Add(grpPem, 0, 1);
            mainLayout.Controls.Add(grpParams, 0, 2);
            mainLayout.Controls.Add(grpData, 0, 3);
            mainLayout.Controls.Add(grpBench, 0, 4);

            tabRsa.Controls.Add(mainLayout);
        }

        private void DisplayRsaKeyInfo(RSA rsa)
        {
            try
            {
                string privPem = _rsaService.ExportPrivateKeyPem(rsa, usePkcs1: true);
                txtPemRaw.Text = privPem;

                byte[] derBytes = _pemService.ExtractDerBytesFromPem(privPem, out string header, out string footer);
                txtPemHexDump.Text = _pemService.GenerateHexDump(derBytes);

                var nodes = _pemService.ParseAsn1Structure(derBytes, header);
                dgvAsn1.Rows.Clear();
                foreach (var n in nodes)
                {
                    dgvAsn1.Rows.Add(n.Offset, n.TagHex, n.TagName, n.Length, n.FieldName, n.ValuePreview, n.Explanation);
                }

                var p = _rsaService.ExtractParameters(rsa);
                txtRsaModulus.Text = $"{p.ModulusN_Hex} ({p.ModulusBytes} bytes = {p.KeySizeBits} bits)";
                txtRsaExponent.Text = $"{p.PublicExponentE_Decimal} (0x{p.PublicExponentE_Hex})";

                var sb = new StringBuilder();
                if (p.IsPrivateKey)
                {
                    sb.AppendLine($"Private Exponent d: {p.PrivateExponentD_Hex?[..40]}... ({p.PrivateExponentD_Bytes} bytes)");
                    sb.AppendLine($"Prime p: {p.PrimeP_Hex?[..32]}... | Prime q: {p.PrimeQ_Hex?[..32]}...");
                    sb.AppendLine($"CRT: dp={p.ExponentDP_Hex?[..20]}... dq={p.ExponentDQ_Hex?[..20]}... qInv={p.InverseQ_Hex?[..20]}...");
                }
                else
                {
                    sb.AppendLine("(Đối tượng hiện tại chỉ chứa Public Key, không có tham số bí mật)");
                }
                txtRsaPrivateParams.Text = sb.ToString();

                SetStatus($"Đã nạp khoá RSA-{rsa.KeySize} và phân tích {nodes.Count} node ASN.1 DER.");
            }
            catch (Exception ex)
            {
                SetStatus($"Lỗi hiển thị RSA: {ex.Message}", isError: true);
            }
        }

        private void BtnGenRsa_Click(object? sender, EventArgs e)
        {
            int bits = cboRsaKeySize.SelectedIndex == 1 ? 4096 : 2048;
            _currentRsa?.Dispose();
            _currentRsa = _rsaService.CreateRsaKey(bits);
            DisplayRsaKeyInfo(_currentRsa);
        }

        private void BtnExportPub_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null) return;
            using var sfd = new SaveFileDialog { Filter = "PEM Public Key (*.pem;*.pub)|*.pem;*.pub", FileName = $"rsa_public_{_currentRsa.KeySize}.pem" };
            if (sfd.ShowDialog() == DialogResult.OK)
            {
                string pem = _rsaService.ExportPublicKeyPem(_currentRsa, usePkcs1: false);
                File.WriteAllText(sfd.FileName, pem, Encoding.UTF8);
                MessageBox.Show($"Đã xuất Public Key ra file:\n{sfd.FileName}", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void BtnExportPriv_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null) return;
            using var sfd = new SaveFileDialog { Filter = "PEM Private Key (*.pem;*.key)|*.pem;*.key", FileName = $"rsa_private_{_currentRsa.KeySize}.pem" };
            if (sfd.ShowDialog() == DialogResult.OK)
            {
                string pem = _rsaService.ExportPrivateKeyPem(_currentRsa, usePkcs1: true);
                File.WriteAllText(sfd.FileName, pem, Encoding.UTF8);
                MessageBox.Show($"Đã xuất Private Key ra file:\n{sfd.FileName}", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }

        private void BtnImportPub_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog { Filter = "PEM Key (*.pem;*.pub;*.crt)|*.pem;*.pub;*.crt" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    string pem = File.ReadAllText(ofd.FileName, Encoding.UTF8);
                    _currentRsa?.Dispose();
                    _currentRsa = _rsaService.ImportFromPem(pem);
                    DisplayRsaKeyInfo(_currentRsa);
                    MessageBox.Show("Nhập Public Key thành công!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Lỗi import Public Key: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void BtnImportPriv_Click(object? sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog { Filter = "PEM Key (*.pem;*.key)|*.pem;*.key" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    string pem = File.ReadAllText(ofd.FileName, Encoding.UTF8);
                    _currentRsa?.Dispose();
                    _currentRsa = _rsaService.ImportFromPem(pem);
                    DisplayRsaKeyInfo(_currentRsa);
                    MessageBox.Show("Nhập Private Key thành công!", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Lỗi import Private Key: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private byte[]? _lastPlainBytes;
        private byte[]? _lastCipherBytes;

        private void BtnEncryptRsaData_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null)
            {
                MessageBox.Show("Chưa khởi tạo khoá RSA.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            try
            {
                byte[] raw = Encoding.UTF8.GetBytes(txtRsaDataInput.Text);
                if (raw.Length > RsaCryptoService.MaxOaepSha256PlaintextBytes)
                {
                    MessageBox.Show($"Dữ liệu dài {raw.Length} bytes, vượt quá giới hạn 190 bytes của RSA-2048 OAEP-SHA256.", "Cảnh báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                _lastPlainBytes = raw;
                _lastCipherBytes = _rsaService.EncryptData(raw, _currentRsa);
                txtRsaCipherBase64.Text = Convert.ToBase64String(_lastCipherBytes);

                using var sfd = new SaveFileDialog { Filter = "Encrypted Data (*.enc)|*.enc", FileName = "rsa_encrypted_payload.enc" };
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    File.WriteAllText(sfd.FileName, txtRsaCipherBase64.Text, Encoding.UTF8);
                    SetStatus($"Đã lưu bản mã RSA ({_lastCipherBytes.Length} bytes) ra file {sfd.FileName}.");
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi mã hoá RSA: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnDecryptRsaData_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null) return;
            using var ofd = new OpenFileDialog { Filter = "Encrypted Data (*.enc)|*.enc" };
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    string b64 = File.ReadAllText(ofd.FileName, Encoding.UTF8).Trim();
                    byte[] cipher = Convert.FromBase64String(b64);
                    byte[] decrypted = _rsaService.DecryptData(cipher, _currentRsa);
                    string decryptedText = Encoding.UTF8.GetString(decrypted);

                    bool match = _lastPlainBytes != null && CryptographicOperations.FixedTimeEquals(_lastPlainBytes, decrypted);
                    lblRsaVerifyResult.Text = match
                        ? $"✓ KHỚP 100%: Giải mã thành công {decrypted.Length} bytes. Nội dung: \"{decryptedText}\""
                        : $"✓ Giải mã thành công ({decrypted.Length} bytes): \"{decryptedText}\"";
                    lblRsaVerifyResult.ForeColor = match ? Color.DarkGreen : Color.Navy;

                    MessageBox.Show($"Giải mã thành công!\n\nNội dung: {decryptedText}\nĐối chiếu nguồn: {(match ? "Khớp 100%" : "Độc lập")}", "Kết quả giải mã", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Lỗi giải mã RSA: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private async void BtnRunRsaBench_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null) return;
            int iters = (int)numBenchIterations.Value;

            SetStatus($"Đang chạy benchmark RSA {iters} lần...");
            lblBenchRatio.Text = "Đang đo đạc...";

            var result = await Task.Run(() => _rsaService.RunBenchmark(_currentRsa, iters));

            lblBenchPublicResult.Text = $"Public Key (c = m^e): {result.AvgPublicKeyMs:F4} ms/op ({result.PublicKeyOpsPerSec:F0} ops/s)";
            lblBenchPrivateResult.Text = $"Private Key (m = c^d): {result.AvgPrivateKeyMs:F4} ms/op ({result.PrivateKeyOpsPerSec:F0} ops/s)";
            lblBenchRatio.Text = $"Private Key chậm hơn: {result.SpeedRatio:F1} lần";
            txtBenchExplanation.Text = result.MathematicalExplanation;

            SetStatus($"Benchmark hoàn thành: Private Key chậm hơn Public Key {result.SpeedRatio:F1} lần.");
        }

        #endregion

        #region TAB 3: HÀM BĂM SHA-256 & HIỆU ỨNG THÁC ĐỔ (UI & LOGIC)

        private TextBox txtShaInputA = null!;
        private TextBox txtShaInputB = null!;
        private TextBox txtShaHexA = null!;
        private TextBox txtShaHexB = null!;
        private TextBox txtShaBinA = null!;
        private TextBox txtShaBinB = null!;
        private Label lblInputDiff = null!;
        private Label lblHammingDistance = null!;
        private RichTextBox rtbHexDiffHighlight = null!;
        private RichTextBox rtbBinDiffHighlight = null!;
        private TextBox txtAvalancheConclusion = null!;

        private void InitializeTabSha256()
        {
            tabSha256.AutoScroll = true;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                AutoScroll = true,
                Padding = new Padding(12)
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            // ================= 1. Inputs & Live SHA-256 =================
            var grpInputs = new GroupBox
            {
                Text = "1. Sinh chuỗi băm SHA-256 theo thời gian thực (Realtime Hash Generation)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tlpInputs = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 2,
                RowCount = 4,
                AutoSize = true
            };
            tlpInputs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            tlpInputs.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            txtShaInputA = new TextBox { Multiline = true, Height = 55, Dock = DockStyle.Fill, Text = "AnToanBaoMatThongTin2026_A", Font = new Font("Segoe UI", 9F) };
            txtShaInputA.TextChanged += (s, e) => UpdateShaRealtime();

            txtShaInputB = new TextBox { Multiline = true, Height = 55, Dock = DockStyle.Fill, Text = "AnToanBaoMatThongTin2026_B", Font = new Font("Segoe UI", 9F) };
            txtShaInputB.TextChanged += (s, e) => UpdateShaRealtime();

            var pnlTopB = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
            var btnCopyAndFlip = new Button { Text = "Sao chép A sang B & Đổi 1 ký tự / 1 bit", AutoSize = true, BackColor = Color.FromArgb(240, 245, 255) };
            btnCopyAndFlip.Click += BtnCopyAndFlip_Click;
            pnlTopB.Controls.Add(btnCopyAndFlip);

            txtShaHexA = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };
            txtShaHexB = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8.5F) };

            txtShaBinA = new TextBox { Multiline = true, Height = 48, Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 7.5F), ScrollBars = ScrollBars.Vertical };
            txtShaBinB = new TextBox { Multiline = true, Height = 48, Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 7.5F), ScrollBars = ScrollBars.Vertical };

            tlpInputs.Controls.Add(new Label { Text = "Dữ liệu gốc (Input A):", Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpInputs.Controls.Add(pnlTopB, 1, 0);

            tlpInputs.Controls.Add(txtShaInputA, 0, 1);
            tlpInputs.Controls.Add(txtShaInputB, 1, 1);

            tlpInputs.Controls.Add(new Label { Text = "SHA-256 (A) - Hex 64 ký tự:", Font = new Font("Segoe UI", 9F) }, 0, 2);
            tlpInputs.Controls.Add(new Label { Text = "SHA-256 (B) - Hex 64 ký tự:", Font = new Font("Segoe UI", 9F) }, 1, 2);

            tlpInputs.Controls.Add(txtShaHexA, 0, 3);
            tlpInputs.Controls.Add(txtShaHexB, 1, 3);

            grpInputs.Controls.Add(tlpInputs);

            // ================= 2. Avalanche Analysis & Visual Highlights =================
            var grpAnalysis = new GroupBox
            {
                Text = "2. Đánh giá Hiệu ứng thác đổ (Avalanche Effect Analysis - Strict Avalanche Criterion)",
                Dock = DockStyle.Fill,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var pnlStats = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(0, 0, 0, 8) };
            lblInputDiff = new Label { Text = "Khác biệt đầu vào: 1 ký tự (1 bit)", AutoSize = true, Margin = new Padding(0, 0, 20, 0), Font = new Font("Segoe UI", 9F) };
            lblHammingDistance = new Label { Text = "Khoảng cách Hamming (Số bit bị đảo): ... / 256 (~50%)", AutoSize = true, Font = new Font("Segoe UI", 9.5F, FontStyle.Bold), ForeColor = Color.DarkRed };
            pnlStats.Controls.AddRange(new Control[] { lblInputDiff, lblHammingDistance });

            var tlpHighlights = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                ColumnCount = 2,
                RowCount = 2,
                Height = 170
            };
            tlpHighlights.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            tlpHighlights.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));

            rtbHexDiffHighlight = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 9F), BackColor = Color.FromArgb(250, 252, 255) };
            rtbBinDiffHighlight = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 7.5F), BackColor = Color.FromArgb(250, 252, 255) };

            tlpHighlights.Controls.Add(new Label { Text = "Trực quan hoá 64 ký tự Hex (Màu đỏ = Ký tự bị đảo):", Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpHighlights.Controls.Add(new Label { Text = "Trực quan hoá 256 bits nhị phân (Màu đỏ = Bit bị đảo):", Font = new Font("Segoe UI", 9F) }, 1, 0);
            tlpHighlights.Controls.Add(rtbHexDiffHighlight, 0, 1);
            tlpHighlights.Controls.Add(rtbBinDiffHighlight, 1, 1);

            txtAvalancheConclusion = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Segoe UI", 9F),
                BackColor = Color.FromArgb(248, 250, 254)
            };

            grpAnalysis.Controls.Add(txtAvalancheConclusion);
            grpAnalysis.Controls.Add(tlpHighlights);
            grpAnalysis.Controls.Add(pnlStats);

            mainLayout.Controls.Add(grpInputs, 0, 0);
            mainLayout.Controls.Add(grpAnalysis, 0, 1);

            tabSha256.Controls.Add(mainLayout);

            UpdateShaRealtime();
        }

        private void BtnCopyAndFlip_Click(object? sender, EventArgs e)
        {
            string a = txtShaInputA.Text;
            if (string.IsNullOrEmpty(a)) a = "Hello";
            // Đổi ký tự cuối từ 'A' thành 'B' hoặc đảo 1 bit
            char last = a[^1];
            char flipped = (char)(last ^ 1);
            txtShaInputB.Text = a[..^1] + flipped;
        }

        private void UpdateShaRealtime()
        {
            try
            {
                var avalanche = _hashService.AnalyzeAvalanche(txtShaInputA.Text, txtShaInputB.Text);

                txtShaHexA.Text = avalanche.HashA_Hex;
                txtShaHexB.Text = avalanche.HashB_Hex;
                txtShaBinA.Text = avalanche.HashA_Binary;
                txtShaBinB.Text = avalanche.HashB_Binary;

                lblInputDiff.Text = $"Khác biệt đầu vào: {avalanche.InputCharDiff} ký tự ({avalanche.InputBitDiff} bit)";
                lblHammingDistance.Text = $"Khoảng cách Hamming (Số bit bị đảo): {avalanche.FlippedBitsCount} / 256 ({avalanche.FlippedBitsPercent:F2}%)";
                txtAvalancheConclusion.Text = avalanche.AvalancheConclusion;

                // Render màu RichTextBox Hex
                rtbHexDiffHighlight.Clear();
                rtbHexDiffHighlight.AppendText("Hash A: " + avalanche.HashA_Hex + "\nHash B: ");
                for (int i = 0; i < 64; i++)
                {
                    char c = avalanche.HashB_Hex[i];
                    bool diff = avalanche.HashA_Hex[i] != c;
                    rtbHexDiffHighlight.SelectionColor = diff ? Color.Red : Color.DarkGreen;
                    rtbHexDiffHighlight.AppendText(c.ToString());
                }

                // Render màu RichTextBox Bin
                rtbBinDiffHighlight.Clear();
                for (int i = 0; i < 256; i++)
                {
                    char bitB = avalanche.HashB_Binary[i];
                    bool diff = avalanche.HashA_Binary[i] != bitB;
                    rtbBinDiffHighlight.SelectionColor = diff ? Color.Red : Color.FromArgb(70, 70, 70);
                    rtbBinDiffHighlight.AppendText(bitB.ToString());
                    if ((i + 1) % 64 == 0) rtbBinDiffHighlight.AppendText("\n");
                    else if ((i + 1) % 8 == 0) rtbBinDiffHighlight.AppendText(" ");
                }
            }
            catch (Exception ex)
            {
                SetStatus($"Lỗi băm SHA-256: {ex.Message}", isError: true);
            }
        }

        #endregion

        #region TAB 4: CHỮ KÝ SỐ RSA & CÁC PHƯƠNG PHÁP KHỬ ĐỊNH TÍNH (UI & LOGIC)

        private TextBox txtSignDoc = null!;
        private TextBox txtSigPkcs1_1 = null!;
        private TextBox txtSigPkcs1_2 = null!;
        private TextBox txtSigPkcs1_3 = null!;
        private Label lblPkcs1Status = null!;

        private TextBox txtSigPss_1 = null!;
        private TextBox txtSigPss_2 = null!;
        private TextBox txtSigPss_3 = null!;
        private Label lblPssVerifyResult = null!;
        private TextBox txtPssExpl = null!;

        private TextBox txtNonceData = null!;
        private TextBox txtNoncePackageDetails = null!;
        private Label lblNonceVerifyResult = null!;
        private TimestampNonceSignedPackage? _currentNoncePackage;

        private void InitializeTabSignature()
        {
            tabSignature.AutoScroll = true;

            var mainLayout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                AutoScroll = true,
                Padding = new Padding(12)
            };
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            mainLayout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            // ================= 1. Chữ ký định tính PKCS#1 v1.5 =================
            var grpPkcs1 = new GroupBox
            {
                Text = "1. Chữ ký số RSA tiêu chuẩn định tính (Deterministic PKCS#1 v1.5)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tlpPkcs1 = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, RowCount = 5, AutoSize = true };
            tlpPkcs1.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            tlpPkcs1.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            txtSignDoc = new TextBox { Dock = DockStyle.Fill, Text = "Hợp đồng chuyển nhượng quyền sở hữu trí tuệ số 2026/HĐ-CNTT.", Font = new Font("Segoe UI", 9F) };
            txtSigPkcs1_1 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8F) };
            txtSigPkcs1_2 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8F) };
            txtSigPkcs1_3 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8F) };

            var flpPkcs1Btns = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
            var btnSignPkcs1All = new Button { Text = "Ký 3 lần liên tiếp (PKCS#1 v1.5)", Width = 230, Height = 28, BackColor = Color.FromArgb(240, 245, 255) };
            btnSignPkcs1All.Click += BtnSignPkcs1All_Click;
            lblPkcs1Status = new Label { Text = "Cả 3 chữ ký sẽ hoàn toàn giống hệt nhau 100% (Tính chất định tính).", AutoSize = true, Font = new Font("Segoe UI", 9F, FontStyle.Italic), ForeColor = Color.DarkBlue, Margin = new Padding(10, 5, 0, 0) };
            flpPkcs1Btns.Controls.AddRange(new Control[] { btnSignPkcs1All, lblPkcs1Status });

            tlpPkcs1.Controls.Add(new Label { Text = "Văn bản cần ký:", Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpPkcs1.Controls.Add(txtSignDoc, 1, 0);

            tlpPkcs1.Controls.Add(new Label { Text = "Thao tác ký:", Font = new Font("Segoe UI", 9F) }, 0, 1);
            tlpPkcs1.Controls.Add(flpPkcs1Btns, 1, 1);

            tlpPkcs1.Controls.Add(new Label { Text = "Chữ ký Lần 1 (Base64):", Font = new Font("Segoe UI", 9F) }, 0, 2);
            tlpPkcs1.Controls.Add(txtSigPkcs1_1, 1, 2);

            tlpPkcs1.Controls.Add(new Label { Text = "Chữ ký Lần 2 (Base64):", Font = new Font("Segoe UI", 9F) }, 0, 3);
            tlpPkcs1.Controls.Add(txtSigPkcs1_2, 1, 3);

            tlpPkcs1.Controls.Add(new Label { Text = "Chữ ký Lần 3 (Base64):", Font = new Font("Segoe UI", 9F) }, 0, 4);
            tlpPkcs1.Controls.Add(txtSigPkcs1_3, 1, 4);

            grpPkcs1.Controls.Add(tlpPkcs1);

            // ================= 2. Phương pháp 1: RSA-PSS =================
            var grpPss = new GroupBox
            {
                Text = "2. Phương pháp 1: Chuẩn mật mã học RSA-PSS (Probabilistic Signature Scheme - PKCS#1 v2.1)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tlpPss = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, RowCount = 5, AutoSize = true };
            tlpPss.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            tlpPss.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var flpPssBtns = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
            var btnSignPss3Times = new Button { Text = "Ký 3 lần liên tiếp bằng RSA-PSS", Width = 230, Height = 28, BackColor = Color.FromArgb(230, 245, 230) };
            btnSignPss3Times.Click += BtnSignPss3Times_Click;

            var btnVerifyPss = new Button { Text = "Xác thực cả 3 chữ ký bằng Public Key", Width = 260, Height = 28, BackColor = Color.FromArgb(240, 240, 255) };
            btnVerifyPss.Click += BtnVerifyPss_Click;

            lblPssVerifyResult = new Label { Text = "Chưa xác thực", AutoSize = true, Font = new Font("Segoe UI", 9F, FontStyle.Bold), Margin = new Padding(10, 5, 0, 0) };
            flpPssBtns.Controls.AddRange(new Control[] { btnSignPss3Times, btnVerifyPss, lblPssVerifyResult });

            txtSigPss_1 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8F) };
            txtSigPss_2 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8F) };
            txtSigPss_3 = new TextBox { Dock = DockStyle.Fill, ReadOnly = true, Font = new Font("Consolas", 8F) };

            txtPssExpl = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                Height = 65,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Segoe UI", 8.5F),
                BackColor = Color.FromArgb(250, 252, 255),
                Text = "CƠ CHẾ RSA-PSS: Thuật toán tự sinh một chuỗi ngẫu nhiên (Random Salt 32 bytes) trước khi ký và kết hợp qua hàm mặt nạ MGF1. Nhờ đó, mỗi lần ký luôn tạo ra chữ ký Base64 khác nhau 100%. Khi xác thực, Public Key tự giải mã mặt nạ, bóc tách Salt và kiểm tra tính toàn vẹn mà không cần truyền riêng Salt."
            };

            tlpPss.Controls.Add(new Label { Text = "Thao tác ký & kiểm tra:", Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpPss.Controls.Add(flpPssBtns, 1, 0);

            tlpPss.Controls.Add(new Label { Text = "Chữ ký PSS #1 (Base64):", Font = new Font("Segoe UI", 9F) }, 0, 1);
            tlpPss.Controls.Add(txtSigPss_1, 1, 1);

            tlpPss.Controls.Add(new Label { Text = "Chữ ký PSS #2 (Base64):", Font = new Font("Segoe UI", 9F) }, 0, 2);
            tlpPss.Controls.Add(txtSigPss_2, 1, 2);

            tlpPss.Controls.Add(new Label { Text = "Chữ ký PSS #3 (Base64):", Font = new Font("Segoe UI", 9F) }, 0, 3);
            tlpPss.Controls.Add(txtSigPss_3, 1, 3);

            tlpPss.Controls.Add(new Label { Text = "Giải thích cơ chế Salt:", Font = new Font("Segoe UI", 9F) }, 0, 4);
            tlpPss.Controls.Add(txtPssExpl, 1, 4);

            grpPss.Controls.Add(tlpPss);

            // ================= 3. Phương pháp 2: Timestamp & Nonce =================
            var grpNonce = new GroupBox
            {
                Text = "3. Phương pháp 2: Bổ sung Nonce & Timestamp ở tầng gói tin ứng dụng (Application Level)",
                Dock = DockStyle.Top,
                AutoSize = true,
                Padding = new Padding(10),
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold)
            };

            var tlpNonce = new TableLayoutPanel { Dock = DockStyle.Top, ColumnCount = 2, RowCount = 3, AutoSize = true };
            tlpNonce.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            tlpNonce.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            txtNonceData = new TextBox { Dock = DockStyle.Fill, Text = "Giao dịch chuyển khoản ngân hàng: Số tiền 50,000,000 VND.", Font = new Font("Segoe UI", 9F) };

            var flpNonceBtns = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true };
            var btnSignNonce = new Button { Text = "Đóng gói & Ký với Timestamp + Nonce", Width = 280, Height = 28, BackColor = Color.FromArgb(235, 245, 255) };
            btnSignNonce.Click += BtnSignNonce_Click;

            var btnVerifyNonce = new Button { Text = "Xác thực gói tin", Width = 150, Height = 28, BackColor = Color.FromArgb(240, 240, 255) };
            btnVerifyNonce.Click += BtnVerifyNonce_Click;

            lblNonceVerifyResult = new Label { Text = "Chưa tạo gói tin", AutoSize = true, Font = new Font("Segoe UI", 9F, FontStyle.Bold), Margin = new Padding(10, 5, 0, 0) };
            flpNonceBtns.Controls.AddRange(new Control[] { btnSignNonce, btnVerifyNonce, lblNonceVerifyResult });

            txtNoncePackageDetails = new TextBox
            {
                Dock = DockStyle.Fill,
                Multiline = true,
                Height = 85,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 8.5F),
                BackColor = Color.FromArgb(250, 252, 255)
            };

            tlpNonce.Controls.Add(new Label { Text = "Dữ liệu giao dịch:", Font = new Font("Segoe UI", 9F) }, 0, 0);
            tlpNonce.Controls.Add(txtNonceData, 1, 0);

            tlpNonce.Controls.Add(new Label { Text = "Thao tác gói tin:", Font = new Font("Segoe UI", 9F) }, 0, 1);
            tlpNonce.Controls.Add(flpNonceBtns, 1, 1);

            tlpNonce.Controls.Add(new Label { Text = "Chi tiết gói tin đã ký:", Font = new Font("Segoe UI", 9F) }, 0, 2);
            tlpNonce.Controls.Add(txtNoncePackageDetails, 1, 2);

            grpNonce.Controls.Add(tlpNonce);

            mainLayout.Controls.Add(grpPkcs1, 0, 0);
            mainLayout.Controls.Add(grpPss, 0, 1);
            mainLayout.Controls.Add(grpNonce, 0, 2);

            tabSignature.Controls.Add(mainLayout);
        }

        private void BtnSignPkcs1All_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null) return;
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(txtSignDoc.Text);
                byte[] s1 = _hashService.SignPkcs1(data, _currentRsa);
                byte[] s2 = _hashService.SignPkcs1(data, _currentRsa);
                byte[] s3 = _hashService.SignPkcs1(data, _currentRsa);

                txtSigPkcs1_1.Text = Convert.ToBase64String(s1);
                txtSigPkcs1_2.Text = Convert.ToBase64String(s2);
                txtSigPkcs1_3.Text = Convert.ToBase64String(s3);

                bool same = (txtSigPkcs1_1.Text == txtSigPkcs1_2.Text) && (txtSigPkcs1_2.Text == txtSigPkcs1_3.Text);
                lblPkcs1Status.Text = same
                    ? "✓ CẢ 3 CHỮ KÝ HOÀN TOÀN GIỐNG HỆT NHAU 100% (Định tính)."
                    : "Lỗi chữ ký!";
                lblPkcs1Status.ForeColor = same ? Color.DarkGreen : Color.Red;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi ký PKCS#1: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private byte[]? _sigPss1Bytes, _sigPss2Bytes, _sigPss3Bytes;
        private byte[]? _pssDocBytes;

        private void BtnSignPss3Times_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null) return;
            try
            {
                _pssDocBytes = Encoding.UTF8.GetBytes(txtSignDoc.Text);
                _sigPss1Bytes = _hashService.SignPss(_pssDocBytes, _currentRsa);
                _sigPss2Bytes = _hashService.SignPss(_pssDocBytes, _currentRsa);
                _sigPss3Bytes = _hashService.SignPss(_pssDocBytes, _currentRsa);

                txtSigPss_1.Text = Convert.ToBase64String(_sigPss1Bytes);
                txtSigPss_2.Text = Convert.ToBase64String(_sigPss2Bytes);
                txtSigPss_3.Text = Convert.ToBase64String(_sigPss3Bytes);

                bool allDifferent = (txtSigPss_1.Text != txtSigPss_2.Text) && (txtSigPss_2.Text != txtSigPss_3.Text) && (txtSigPss_1.Text != txtSigPss_3.Text);
                lblPssVerifyResult.Text = allDifferent
                    ? "✓ Đã sinh 3 chữ ký Base64 KHÁC NHAU HOÀN TOÀN (Bấm 'Xác thực' để kiểm tra)"
                    : "Lỗi chữ ký!";
                lblPssVerifyResult.ForeColor = allDifferent ? Color.DarkBlue : Color.Red;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi ký RSA-PSS: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnVerifyPss_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null || _pssDocBytes == null || _sigPss1Bytes == null || _sigPss2Bytes == null || _sigPss3Bytes == null)
            {
                MessageBox.Show("Vui lòng bấm 'Ký 3 lần' trước khi xác thực.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            bool v1 = _hashService.VerifyPss(_pssDocBytes, _sigPss1Bytes, _currentRsa);
            bool v2 = _hashService.VerifyPss(_pssDocBytes, _sigPss2Bytes, _currentRsa);
            bool v3 = _hashService.VerifyPss(_pssDocBytes, _sigPss3Bytes, _currentRsa);

            if (v1 && v2 && v3)
            {
                lblPssVerifyResult.Text = "✓ CẢ 3 CHỮ KÝ ĐỀU HỢP LỆ (VALID) BẰNG PUBLIC KEY!";
                lblPssVerifyResult.ForeColor = Color.DarkGreen;
                MessageBox.Show("Xác nhận thành công:\nDù cả 3 chữ ký có chuỗi byte khác nhau hoàn toàn do Random Salt, Public Key vẫn xác thực thành công 100%!", "Thành công", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                lblPssVerifyResult.Text = "Xác thực thất bại!";
                lblPssVerifyResult.ForeColor = Color.Red;
            }
        }

        private void BtnSignNonce_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null) return;
            try
            {
                _currentNoncePackage = _hashService.CreateTimestampNoncePackage(txtNonceData.Text, _currentRsa);

                var sb = new StringBuilder();
                sb.AppendLine($"Dữ liệu gốc: {_currentNoncePackage.OriginalData}");
                sb.AppendLine($"Timestamp UTC: {_currentNoncePackage.TimestampUtc:yyyy-MM-dd HH:mm:ss.fff} (Ticks: {_currentNoncePackage.TimestampUtcTicks})");
                sb.AppendLine($"Random Nonce (16 bytes): {_currentNoncePackage.NonceHex}");
                sb.AppendLine($"Payload băm và ký: {_currentNoncePackage.PayloadToSign}");
                sb.AppendLine($"Chữ ký số (Base64): {_currentNoncePackage.SignatureBase64}");

                txtNoncePackageDetails.Text = sb.ToString();
                lblNonceVerifyResult.Text = "Đã tạo gói tin mới với Nonce & Timestamp duy nhất.";
                lblNonceVerifyResult.ForeColor = Color.DarkBlue;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Lỗi tạo gói tin: {ex.Message}", "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnVerifyNonce_Click(object? sender, EventArgs e)
        {
            if (_currentRsa == null || _currentNoncePackage == null)
            {
                MessageBox.Show("Chưa có gói tin nào được ký.", "Thông báo", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            bool valid = _hashService.VerifyTimestampNoncePackage(_currentNoncePackage, _currentRsa);
            lblNonceVerifyResult.Text = valid
                ? "✓ GÓI TIN HỢP LỆ (VALID): Chữ ký đúng, chống phát lại thành công!"
                : "Gói tin không hợp lệ hoặc đã bị sửa đổi!";
            lblNonceVerifyResult.ForeColor = valid ? Color.DarkGreen : Color.Red;

            MessageBox.Show(lblNonceVerifyResult.Text, "Kết quả xác thực", MessageBoxButtons.OK,
                valid ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        #endregion
    }
}
