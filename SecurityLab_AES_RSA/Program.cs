using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using SecurityLab_AES_RSA.Services;
using SecurityLab_AES_RSA.UI;

namespace SecurityLab_AES_RSA
{
    static class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        private const int ATTACH_PARENT_PROCESS = -1;

        /// <summary>
        /// Điểm khởi động chính của ứng dụng.
        /// Hỗ trợ cả giao diện đồ hoạ WinForms và chế độ dòng lệnh tự động (--self-test).
        /// </summary>
        [STAThread]
        static int Main(string[] args)
        {
            if (args != null && args.Any(a => a.Equals("--self-test", StringComparison.OrdinalIgnoreCase) 
                                           || a.Equals("-t", StringComparison.OrdinalIgnoreCase)))
            {
                // Gắn vào console cha hiện hành của terminal để xuất output trực tiếp
                AttachConsole(ATTACH_PARENT_PROCESS);
                try
                {
                    var stdOut = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
                    var stdErr = new System.IO.StreamWriter(Console.OpenStandardError()) { AutoFlush = true };
                    Console.SetOut(stdOut);
                    Console.SetError(stdErr);
                }
                catch { }

                return CliTestRunner.RunAllTestsAsync().GetAwaiter().GetResult();
            }

            if (args != null && args.Any(a => a.Equals("--help", StringComparison.OrdinalIgnoreCase) 
                                           || a.Equals("-h", StringComparison.OrdinalIgnoreCase)))
            {
                if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
                Console.WriteLine("SECURITY LAB - HƯỚNG DẪN DÒNG LỆNH");
                Console.WriteLine("--------------------------------------------------");
                Console.WriteLine("  SecurityLab_AES_RSA.exe             : Khởi chạy giao diện đồ hoạ WinForms");
                Console.WriteLine("  SecurityLab_AES_RSA.exe --self-test : Chạy kiểm thử tự động toàn diện và xuất báo cáo");
                Console.WriteLine("  SecurityLab_AES_RSA.exe --help      : Hiển thị thông tin trợ giúp");
                return 0;
            }

            ApplicationConfiguration.Initialize();
            Application.Run(new MainForm());
            return 0;
        }
    }
}