using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SecurityLab_AES_RSA.Models;

namespace SecurityLab_AES_RSA.Services
{
    /// <summary>
    /// Dịch vụ Mật mã học RSA: Sinh cặp khoá, xuất/nhập PEM, trích xuất tham số toán học (n, e, d, p, q),
    /// mã hoá/giải mã khối dữ liệu <= 190 bytes và thực nghiệm so sánh tốc độ Public Key vs Private Key.
    /// </summary>
    public class RsaCryptoService
    {
        public const int MaxOaepSha256PlaintextBytes = 190; // Ràng buộc lý thuyết đối với RSA-2048 OAEP-SHA256 (256 - 64 - 2 = 190)

        /// <summary>
        /// Sinh cặp khoá RSA với độ dài bit chỉ định (2048-bit hoặc 4096-bit).
        /// </summary>
        public RSA CreateRsaKey(int keySizeBits = 2048)
        {
            if (keySizeBits < 2048)
            {
                throw new ArgumentException("Để đảm bảo an toàn thông tin, độ dài khoá RSA tối thiểu phải từ 2048 bit trở lên.", nameof(keySizeBits));
            }

            return RSA.Create(keySizeBits);
        }

        /// <summary>
        /// Xuất khoá công khai ra định dạng chuỗi PEM.
        /// </summary>
        public string ExportPublicKeyPem(RSA rsa, bool usePkcs1 = false)
        {
            return usePkcs1 
                ? rsa.ExportRSAPublicKeyPem() 
                : rsa.ExportSubjectPublicKeyInfoPem();
        }

        /// <summary>
        /// Xuất khoá riêng tư ra định dạng chuỗi PEM.
        /// </summary>
        public string ExportPrivateKeyPem(RSA rsa, bool usePkcs1 = true)
        {
            return usePkcs1 
                ? rsa.ExportRSAPrivateKeyPem() 
                : rsa.ExportPkcs8PrivateKeyPem();
        }

        /// <summary>
        /// Nhập khoá từ chuỗi nội dung file PEM (tự động nhận diện Public / Private và PKCS#1 / PKCS#8 / SPKI).
        /// </summary>
        public RSA ImportFromPem(string pemText)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pemText);
            return rsa;
        }

        /// <summary>
        /// Trích xuất toàn bộ các tham số toán học từ RSA (Modulus n, Public Exponent e, Private Exponent d, Primes p, q, CRT...).
        /// </summary>
        public ExtractedRsaParams ExtractParameters(RSA rsa)
        {
            var result = new ExtractedRsaParams
            {
                KeySizeBits = rsa.KeySize
            };

            try
            {
                // Thử trích xuất khoá riêng tư kèm toàn bộ tham số
                var privParams = rsa.ExportParameters(includePrivateParameters: true);
                result.IsPrivateKey = true;

                if (privParams.Modulus != null)
                {
                    result.ModulusN_Hex = Convert.ToHexString(privParams.Modulus);
                    result.ModulusN_Base64 = Convert.ToBase64String(privParams.Modulus);
                    result.ModulusBytes = privParams.Modulus.Length;
                }

                if (privParams.Exponent != null)
                {
                    result.PublicExponentE_Hex = Convert.ToHexString(privParams.Exponent);
                    result.PublicExponentE_Decimal = DecodeBigEndianInteger(privParams.Exponent);
                }

                if (privParams.D != null)
                {
                    result.PrivateExponentD_Hex = Convert.ToHexString(privParams.D);
                    result.PrivateExponentD_Bytes = privParams.D.Length;
                }

                if (privParams.P != null) result.PrimeP_Hex = Convert.ToHexString(privParams.P);
                if (privParams.Q != null) result.PrimeQ_Hex = Convert.ToHexString(privParams.Q);
                if (privParams.DP != null) result.ExponentDP_Hex = Convert.ToHexString(privParams.DP);
                if (privParams.DQ != null) result.ExponentDQ_Hex = Convert.ToHexString(privParams.DQ);
                if (privParams.InverseQ != null) result.InverseQ_Hex = Convert.ToHexString(privParams.InverseQ);
            }
            catch (CryptographicException)
            {
                // Nếu đối tượng chỉ chứa Public Key
                var pubParams = rsa.ExportParameters(includePrivateParameters: false);
                result.IsPrivateKey = false;

                if (pubParams.Modulus != null)
                {
                    result.ModulusN_Hex = Convert.ToHexString(pubParams.Modulus);
                    result.ModulusN_Base64 = Convert.ToBase64String(pubParams.Modulus);
                    result.ModulusBytes = pubParams.Modulus.Length;
                }

                if (pubParams.Exponent != null)
                {
                    result.PublicExponentE_Hex = Convert.ToHexString(pubParams.Exponent);
                    result.PublicExponentE_Decimal = DecodeBigEndianInteger(pubParams.Exponent);
                }
            }

            return result;
        }

        /// <summary>
        /// Mã hoá mảng dữ liệu đầu vào <= 190 bytes (theo chuẩn RSA-2048 OAEP-SHA256).
        /// </summary>
        public byte[] EncryptData(byte[] plainBytes, RSA rsa)
        {
            if (plainBytes == null || plainBytes.Length == 0)
            {
                throw new ArgumentException("Dữ liệu cần mã hoá không được để trống.", nameof(plainBytes));
            }

            // Với khoá 2048-bit (256 bytes): Giới hạn OAEP-SHA256 là 256 - 2 * 32 - 2 = 190 bytes
            int maxBytes = (rsa.KeySize / 8) - (2 * 32) - 2;
            if (plainBytes.Length > maxBytes)
            {
                throw new ArgumentException($"Dữ liệu vượt quá kích thước tối đa cho phép của RSA-{rsa.KeySize} với OAEP-SHA256 ({plainBytes.Length} bytes > {maxBytes} bytes).", nameof(plainBytes));
            }

            return rsa.Encrypt(plainBytes, RSAEncryptionPadding.OaepSHA256);
        }

        /// <summary>
        /// Giải mã mảng byte Ciphertext trả về dữ liệu gốc ban đầu.
        /// </summary>
        public byte[] DecryptData(byte[] cipherBytes, RSA rsa)
        {
            if (cipherBytes == null || cipherBytes.Length == 0)
            {
                throw new ArgumentException("Ciphertext không được để trống.", nameof(cipherBytes));
            }

            return rsa.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
        }

        /// <summary>
        /// Thử nghiệm hiệu năng (Benchmark) so sánh tốc độ xử lý giữa:
        /// 1. Thao tác khoá công khai (Public Key: x^e mod n) với e = 65537 rất nhỏ.
        /// 2. Thao tác khoá riêng tư (Private Key: y^d mod n) với d rất lớn (khoảng 2048-bit).
        /// </summary>
        public RsaBenchmarkResult RunBenchmark(RSA rsa, int iterations = 500)
        {
            if (iterations <= 0) iterations = 100;

            // Chuẩn bị dữ liệu mẫu 32 bytes (tương đương kích thước khoá AES-256)
            byte[] sampleData = new byte[32];
            RandomNumberGenerator.Fill(sampleData);

            // 1. Đo thời gian mã hoá bằng Public Key (c = m^e mod n)
            byte[] cipher = rsa.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);

            var swPublic = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = rsa.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);
            }
            swPublic.Stop();

            // 2. Đo thời gian giải mã bằng Private Key (m = c^d mod n)
            var swPrivate = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                _ = rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            }
            swPrivate.Stop();

            double avgPubMs = swPublic.Elapsed.TotalMilliseconds / iterations;
            double avgPrivMs = swPrivate.Elapsed.TotalMilliseconds / iterations;
            double pubOps = swPublic.Elapsed.TotalSeconds > 0 ? iterations / swPublic.Elapsed.TotalSeconds : 0;
            double privOps = swPrivate.Elapsed.TotalSeconds > 0 ? iterations / swPrivate.Elapsed.TotalSeconds : 0;
            double ratio = avgPubMs > 0 ? avgPrivMs / avgPubMs : 0;

            string explanation = 
                $"GIẢI THÍCH NGUYÊN NHÂN TOÁN HỌC:\n" +
                $"1. Thao tác với Public Key tính luỹ thừa modulo c = m^e mod n với e = 65537 (0x010001 = 2^16 + 1).\n" +
                $"   Dạng nhị phân của e chỉ có đúng 17 bit và chỉ có 2 bit '1' (Trọng số Hamming = 2).\n" +
                $"   Theo thuật toán Bình phương và Nhân (Square-and-Multiply), chỉ cần thực hiện đúng 16 phép bình phương và 1 phép nhân modulo!\n\n" +
                $"2. Thao tác với Private Key tính y^d mod n với d là số nguyên khổng lồ xấp xỉ 2048 bit.\n" +
                $"   Trọng số Hamming của d xấp xỉ 1024 bit '1'. Kể cả khi áp dụng Định lý số dư Trung Hoa (CRT) chia nhỏ thành 2 luồng tính toán mod p và mod q (mỗi số 1024-bit),\n" +
                $"   mỗi nhánh vẫn đòi hỏi ~1024 phép bình phương và ~512 phép nhân các số nguyên lớn 1024-bit.\n\n" +
                $"KẾT QUẢ THỰC TẾ: Thao tác khoá riêng tư (Private Key) chậm hơn khoá công khai (Public Key) xấp xỉ {ratio:F1} lần!";

            return new RsaBenchmarkResult
            {
                Iterations = iterations,
                TotalPublicKeyTime = swPublic.Elapsed,
                AvgPublicKeyMs = avgPubMs,
                PublicKeyOpsPerSec = pubOps,
                TotalPrivateKeyTime = swPrivate.Elapsed,
                AvgPrivateKeyMs = avgPrivMs,
                PrivateKeyOpsPerSec = privOps,
                SpeedRatio = ratio,
                MathematicalExplanation = explanation
            };
        }

        private static long DecodeBigEndianInteger(byte[] bytes)
        {
            long val = 0;
            foreach (byte b in bytes)
            {
                val = (val << 8) | b;
            }
            return val;
        }
    }
}
