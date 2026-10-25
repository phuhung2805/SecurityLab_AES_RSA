using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using SecurityLab_AES_RSA.Models;

namespace SecurityLab_AES_RSA.Services
{
    /// <summary>
    /// Dịch vụ Mật mã học AES: Xử lý sinh khoá, lưu/nhập khoá, mã hoá/giải mã văn bản và file dung lượng lớn.
    /// Sử dụng thuật toán AES (Advanced Encryption Standard) chế độ CBC với đệm PKCS7.
    /// </summary>
    public class AesCryptoService
    {
        public const int ChunkBufferSize = 1024 * 1024; // Buffer chuẩn 1 MB để tối ưu I/O và RAM

        /// <summary>
        /// Sinh khoá AES và IV ngẫu nhiên theo độ dài bit chỉ định (128, 192, hoặc 256 bit).
        /// IV luôn là 16 bytes (128 bit) theo tiêu chuẩn khối của AES.
        /// </summary>
        public AesKeyBundle GenerateKey(int keySizeBits = 256)
        {
            if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256)
            {
                throw new ArgumentException("Độ dài khoá AES chỉ hỗ trợ 128, 192 hoặc 256 bit.", nameof(keySizeBits));
            }

            using var aes = Aes.Create();
            aes.KeySize = keySizeBits;
            aes.GenerateKey();
            aes.GenerateIV();

            return new AesKeyBundle
            {
                KeySizeBits = keySizeBits,
                KeyBase64 = Convert.ToBase64String(aes.Key),
                KeyHex = Convert.ToHexString(aes.Key),
                IvBase64 = Convert.ToBase64String(aes.IV),
                IvHex = Convert.ToHexString(aes.IV),
                CreatedAtUtc = DateTime.UtcNow
            };
        }

        /// <summary>
        /// Lưu gói khoá AES ra file định dạng .aeskey (JSON chuẩn).
        /// </summary>
        public async Task ExportKeyToFileAsync(AesKeyBundle bundle, string filePath)
        {
            var options = new JsonSerializerOptions { WriteIndented = true };
            string json = JsonSerializer.Serialize(bundle, options);
            await File.WriteAllTextAsync(filePath, json, Encoding.UTF8);
        }

        /// <summary>
        /// Nạp lại gói khoá AES từ file .aeskey.
        /// </summary>
        public async Task<AesKeyBundle> ImportKeyFromFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("Không tìm thấy file khoá AES.", filePath);
            }

            string json = await File.ReadAllTextAsync(filePath, Encoding.UTF8);
            var bundle = JsonSerializer.Deserialize<AesKeyBundle>(json);
            if (bundle == null || string.IsNullOrWhiteSpace(bundle.KeyBase64) || string.IsNullOrWhiteSpace(bundle.IvBase64))
            {
                throw new InvalidDataException("Định dạng file khoá AES không hợp lệ.");
            }

            return bundle;
        }

        /// <summary>
        /// Mã hoá văn bản UTF-8 bằng AES-CBC-PKCS7, trả về chuỗi Ciphertext Base64.
        /// </summary>
        public string EncryptText(string plainText, byte[] key, byte[] iv)
        {
            if (string.IsNullOrEmpty(plainText)) return string.Empty;

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return Convert.ToBase64String(cipherBytes);
        }

        /// <summary>
        /// Giải mã chuỗi Ciphertext Base64 bằng AES-CBC-PKCS7, trả về văn bản gốc UTF-8.
        /// </summary>
        public string DecryptText(string cipherBase64, byte[] key, byte[] iv)
        {
            if (string.IsNullOrEmpty(cipherBase64)) return string.Empty;

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            byte[] cipherBytes = Convert.FromBase64String(cipherBase64);
            byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(plainBytes);
        }

        /// <summary>
        /// Sinh file mẫu lớn (Dummy File) dung lượng tuỳ ý (100MB, 500MB, 1GB, 2GB...)
        /// theo luồng khối 1MB mà không chiếm dụng nhiều bộ nhớ RAM.
        /// </summary>
        public async Task GenerateDummyFileAsync(
            string filePath, 
            long targetSizeBytes, 
            IProgress<(long written, long total, double percent)>? progress = null, 
            CancellationToken cancellationToken = default)
        {
            var buffer = new byte[ChunkBufferSize];
            long bytesWritten = 0;

            // Đảm bảo thư mục cha tồn tại
            string? dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await using var fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None, ChunkBufferSize, useAsync: true);

            while (bytesWritten < targetSizeBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int bytesToWrite = (int)Math.Min(ChunkBufferSize, targetSizeBytes - bytesWritten);
                // Sinh dữ liệu giả lập có quy luật ngẫu nhiên nhẹ
                Random.Shared.NextBytes(buffer.AsSpan(0, bytesToWrite));

                await fs.WriteAsync(buffer.AsMemory(0, bytesToWrite), cancellationToken);
                bytesWritten += bytesToWrite;

                double percent = (double)bytesWritten / targetSizeBytes * 100.0;
                progress?.Report((bytesWritten, targetSizeBytes, percent));
            }

            await fs.FlushAsync(cancellationToken);
        }

        /// <summary>
        /// Mã hoá file dung lượng lớn (Hàng GB) bằng FileStream + CryptoStream với buffer 1MB.
        /// Không tải toàn bộ file vào RAM để phòng tránh OutOfMemoryException.
        /// Đo thời gian và thông lượng (MB/s), đồng thời tính mã băm SHA-256 của file đích.
        /// </summary>
        public async Task<FileCryptoResult> EncryptFileAsync(
            string inputFilePath, 
            string outputFilePath, 
            byte[] key, 
            byte[] iv, 
            IProgress<(long processed, long total, double speedMbPerSec)>? progress = null, 
            CancellationToken cancellationToken = default)
        {
            if (!File.Exists(inputFilePath))
            {
                throw new FileNotFoundException("File nguồn không tồn tại.", inputFilePath);
            }

            long totalBytes = new FileInfo(inputFilePath).Length;
            var stopwatch = Stopwatch.StartNew();

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            await using (var inStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBufferSize, useAsync: true))
            await using (var outStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None, ChunkBufferSize, useAsync: true))
            await using (var cryptoStream = new CryptoStream(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                byte[] buffer = new byte[ChunkBufferSize];
                long bytesProcessed = 0;
                int bytesRead;

                while ((bytesRead = await inStream.ReadAsync(buffer.AsMemory(0, ChunkBufferSize), cancellationToken)) > 0)
                {
                    await cryptoStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                    bytesProcessed += bytesRead;

                    double elapsedSec = stopwatch.Elapsed.TotalSeconds;
                    double speed = elapsedSec > 0 ? (bytesProcessed / (1024.0 * 1024.0)) / elapsedSec : 0;
                    progress?.Report((bytesProcessed, totalBytes, speed));
                }

                await cryptoStream.FlushFinalBlockAsync(cancellationToken);
            }
            stopwatch.Stop();

            // Tính SHA-256 của file mã hoá đầu ra (sau khi luồng ghi đã đóng hoàn toàn)
            string hashResult = await ComputeFileSha256Async(outputFilePath, cancellationToken);

            double finalElapsedSec = Math.Max(0.001, stopwatch.Elapsed.TotalSeconds);
            double finalSpeed = (totalBytes / (1024.0 * 1024.0)) / finalElapsedSec;

            return new FileCryptoResult
            {
                Success = true,
                FilePath = outputFilePath,
                FileSizeBytes = new FileInfo(outputFilePath).Length,
                Elapsed = stopwatch.Elapsed,
                SpeedMBps = finalSpeed,
                Sha256Hash = hashResult
            };
        }

        /// <summary>
        /// Giải mã file dung lượng lớn bằng FileStream + CryptoStream với buffer 1MB.
        /// </summary>
        public async Task<FileCryptoResult> DecryptFileAsync(
            string inputFilePath, 
            string outputFilePath, 
            byte[] key, 
            byte[] iv, 
            IProgress<(long processed, long total, double speedMbPerSec)>? progress = null, 
            CancellationToken cancellationToken = default)
        {
            if (!File.Exists(inputFilePath))
            {
                throw new FileNotFoundException("File mã hoá không tồn tại.", inputFilePath);
            }

            long totalBytes = new FileInfo(inputFilePath).Length;
            var stopwatch = Stopwatch.StartNew();

            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            await using (var inStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBufferSize, useAsync: true))
            await using (var cryptoStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
            await using (var outStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write, FileShare.None, ChunkBufferSize, useAsync: true))
            {
                byte[] buffer = new byte[ChunkBufferSize];
                long bytesProcessed = 0;
                int bytesRead;

                while ((bytesRead = await cryptoStream.ReadAsync(buffer.AsMemory(0, ChunkBufferSize), cancellationToken)) > 0)
                {
                    await outStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                    bytesProcessed += bytesRead;

                    double elapsedSec = stopwatch.Elapsed.TotalSeconds;
                    double speed = elapsedSec > 0 ? (inStream.Position / (1024.0 * 1024.0)) / elapsedSec : 0;
                    progress?.Report((inStream.Position, totalBytes, speed));
                }

                await outStream.FlushAsync(cancellationToken);
            }
            stopwatch.Stop();

            string hashResult = await ComputeFileSha256Async(outputFilePath, cancellationToken);

            double finalElapsedSec = Math.Max(0.001, stopwatch.Elapsed.TotalSeconds);
            double finalSpeed = (totalBytes / (1024.0 * 1024.0)) / finalElapsedSec;

            return new FileCryptoResult
            {
                Success = true,
                FilePath = outputFilePath,
                FileSizeBytes = new FileInfo(outputFilePath).Length,
                Elapsed = stopwatch.Elapsed,
                SpeedMBps = finalSpeed,
                Sha256Hash = hashResult
            };
        }

        /// <summary>
        /// Đối chiếu hai file theo từng khối byte (Streaming Buffer Compare) và tính đồng thời SHA-256.
        /// Đảm bảo không nạp toàn bộ file vào RAM và phát hiện chính xác mọi byte sai khác nếu có.
        /// </summary>
        public async Task<FileCompareResult> CompareFilesAsync(
            string path1, 
            string path2, 
            IProgress<(long compared, long total)>? progress = null, 
            CancellationToken cancellationToken = default)
        {
            if (!File.Exists(path1)) throw new FileNotFoundException("File 1 không tồn tại.", path1);
            if (!File.Exists(path2)) throw new FileNotFoundException("File 2 không tồn tại.", path2);

            var fi1 = new FileInfo(path1);
            var fi2 = new FileInfo(path2);

            var stopwatch = Stopwatch.StartNew();

            using var hash1 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            using var hash2 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

            await using var fs1 = new FileStream(path1, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBufferSize, useAsync: true);
            await using var fs2 = new FileStream(path2, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBufferSize, useAsync: true);

            byte[] buf1 = new byte[ChunkBufferSize];
            byte[] buf2 = new byte[ChunkBufferSize];

            long totalCompared = 0;
            long mismatchCount = 0;
            long firstMismatch = -1;
            long maxLen = Math.Max(fi1.Length, fi2.Length);

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int r1 = await fs1.ReadAsync(buf1.AsMemory(0, ChunkBufferSize), cancellationToken);
                int r2 = await fs2.ReadAsync(buf2.AsMemory(0, ChunkBufferSize), cancellationToken);

                if (r1 > 0) hash1.AppendData(buf1, 0, r1);
                if (r2 > 0) hash2.AppendData(buf2, 0, r2);

                int minR = Math.Min(r1, r2);
                for (int i = 0; i < minR; i++)
                {
                    if (buf1[i] != buf2[i])
                    {
                        mismatchCount++;
                        if (firstMismatch == -1)
                        {
                            firstMismatch = totalCompared + i;
                        }
                    }
                }

                if (r1 != r2)
                {
                    mismatchCount += Math.Abs(r1 - r2);
                    if (firstMismatch == -1)
                    {
                        firstMismatch = totalCompared + minR;
                    }
                }

                totalCompared += minR;
                progress?.Report((totalCompared, maxLen));

                if (r1 == 0 && r2 == 0) break;
            }

            stopwatch.Stop();

            string sha1 = Convert.ToHexString(hash1.GetHashAndReset());
            string sha2 = Convert.ToHexString(hash2.GetHashAndReset());
            bool identical = (fi1.Length == fi2.Length) && (mismatchCount == 0) && (sha1 == sha2);

            string conclusion = identical
                ? $"XÁC NHẬN TOÀN VẸN 100%: File sau giải mã khớp hoàn toàn với file gốc trên từng byte (Đã kiểm tra {totalCompared:N0} bytes, 0 byte lỗi, mã băm SHA-256 trùng khớp tuyệt đối)."
                : $"CẢNH BÁO SAI KHÁC: Phát hiện {mismatchCount:N0} bytes khác nhau. Vị trí sai khác đầu tiên tại byte offset #{firstMismatch:N0}.";

            return new FileCompareResult
            {
                AreIdentical = identical,
                TotalBytesCompared = totalCompared,
                MismatchCount = mismatchCount,
                FirstMismatchOffset = firstMismatch,
                Sha256Source = sha1,
                Sha256Decrypted = sha2,
                Elapsed = stopwatch.Elapsed,
                Conclusion = conclusion
            };
        }

        /// <summary>
        /// Tính mã băm SHA-256 của file theo cơ chế streaming 1MB buffer.
        /// </summary>
        public async Task<string> ComputeFileSha256Async(string filePath, CancellationToken cancellationToken = default)
        {
            using var sha256 = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBufferSize, useAsync: true);
            byte[] buffer = new byte[ChunkBufferSize];
            int bytesRead;

            while ((bytesRead = await fs.ReadAsync(buffer.AsMemory(0, ChunkBufferSize), cancellationToken)) > 0)
            {
                sha256.AppendData(buffer, 0, bytesRead);
            }

            return Convert.ToHexString(sha256.GetHashAndReset());
        }
    }
}
