namespace SecurityLab_AES_RSA.UI
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.tabControlMain = new System.Windows.Forms.TabControl();
            this.tabAes = new System.Windows.Forms.TabPage();
            this.tabRsa = new System.Windows.Forms.TabPage();
            this.tabSha256 = new System.Windows.Forms.TabPage();
            this.tabSignature = new System.Windows.Forms.TabPage();
            this.pnlTopBanner = new System.Windows.Forms.Panel();
            this.lblTitle = new System.Windows.Forms.Label();
            this.lblSubtitle = new System.Windows.Forms.Label();
            this.pnlStatus = new System.Windows.Forms.Panel();
            this.lblStatus = new System.Windows.Forms.Label();

            // 
            // pnlTopBanner
            // 
            this.pnlTopBanner.BackColor = System.Drawing.Color.FromArgb(24, 43, 73);
            this.pnlTopBanner.Dock = System.Windows.Forms.DockStyle.Top;
            this.pnlTopBanner.Height = 70;
            this.pnlTopBanner.Padding = new System.Windows.Forms.Padding(18, 10, 18, 10);

            this.lblTitle.Text = "SECURITY LAB: MÃ HOÁ AES, RSA, SHA-256 & CHỮ KÝ SỐ";
            this.lblTitle.Font = new System.Drawing.Font("Segoe UI", 13.5F, System.Drawing.FontStyle.Bold);
            this.lblTitle.ForeColor = System.Drawing.Color.White;
            this.lblTitle.AutoSize = true;
            this.lblTitle.Location = new System.Drawing.Point(18, 10);

            this.lblSubtitle.Text = "Phần mềm thực nghiệm Môn An toàn và Bảo mật thông tin | Kiến trúc .NET 8.0 Bất đồng bộ";
            this.lblSubtitle.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Regular);
            this.lblSubtitle.ForeColor = System.Drawing.Color.FromArgb(190, 215, 250);
            this.lblSubtitle.AutoSize = true;
            this.lblSubtitle.Location = new System.Drawing.Point(19, 38);

            this.pnlTopBanner.Controls.Add(this.lblTitle);
            this.pnlTopBanner.Controls.Add(this.lblSubtitle);

            // 
            // pnlStatus
            // 
            this.pnlStatus.BackColor = System.Drawing.Color.FromArgb(240, 243, 248);
            this.pnlStatus.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.pnlStatus.Height = 32;
            this.pnlStatus.Padding = new System.Windows.Forms.Padding(12, 6, 12, 6);

            this.lblStatus.Text = "Sẵn sàng thực thi các tác vụ bảo mật.";
            this.lblStatus.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Regular);
            this.lblStatus.ForeColor = System.Drawing.Color.FromArgb(50, 60, 80);
            this.lblStatus.AutoSize = true;
            this.lblStatus.Location = new System.Drawing.Point(12, 7);

            this.pnlStatus.Controls.Add(this.lblStatus);

            // 
            // tabControlMain
            // 
            this.tabControlMain.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tabControlMain.Font = new System.Drawing.Font("Segoe UI", 9.5F, System.Drawing.FontStyle.Regular);
            this.tabControlMain.ItemSize = new System.Drawing.Size(260, 34);
            this.tabControlMain.SizeMode = System.Windows.Forms.TabSizeMode.Fixed;
            this.tabControlMain.Controls.Add(this.tabAes);
            this.tabControlMain.Controls.Add(this.tabRsa);
            this.tabControlMain.Controls.Add(this.tabSha256);
            this.tabControlMain.Controls.Add(this.tabSignature);

            this.tabAes.Text = "1. Mã hoá Đối xứng AES";
            this.tabRsa.Text = "2. RSA & Phân tích PEM";
            this.tabSha256.Text = "3. SHA-256 & Avalanche";
            this.tabSignature.Text = "4. Chữ ký số RSA";

            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 17F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1220, 840);
            this.MinimumSize = new System.Drawing.Size(1080, 760);
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Security Lab - Môn An toàn và Bảo mật thông tin (AES & RSA)";
            this.Font = new System.Drawing.Font("Segoe UI", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point);

            this.Controls.Add(this.tabControlMain);
            this.Controls.Add(this.pnlStatus);
            this.Controls.Add(this.pnlTopBanner);

            this.InitializeTabAes();
            this.InitializeTabRsa();
            this.InitializeTabSha256();
            this.InitializeTabSignature();
        }

        private System.Windows.Forms.Panel pnlTopBanner;
        private System.Windows.Forms.Label lblTitle;
        private System.Windows.Forms.Label lblSubtitle;
        private System.Windows.Forms.Panel pnlStatus;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.TabControl tabControlMain;
        private System.Windows.Forms.TabPage tabAes;
        private System.Windows.Forms.TabPage tabRsa;
        private System.Windows.Forms.TabPage tabSha256;
        private System.Windows.Forms.TabPage tabSignature;
    }
}
