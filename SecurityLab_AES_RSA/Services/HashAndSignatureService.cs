using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using SecurityLab_AES_RSA.Models;

namespace SecurityLab_AES_RSA.Services
{
    /// <summary>
    /// Dịch vụ tính toán hàm băm SHA-256, phân tích hiệu ứng thác đổ (Avalanche Effect),
    /// và demo Chữ ký số RSA tiêu chuẩn (PKCS#1 v1.5) cùng 2 phương pháp sinh chữ ký ngẫu nhiên khác nhau cho cùng một văn bản (RSA-PSS và Timestamp/Nonce).
    /// </summary>
    public class HashAndSignatureService
    {
        #region TAB 3: SHA-256 & AVALANCHE EFFECT

        /// <summary>
        /// Tính mã băm SHA-256 của chuỗi văn bản UTF-8, trả về mảng byte, chuỗi Hex 64 ký tự và chuỗi nhị phân 256-bit.
        /// </summary>
        public (byte[] hashBytes, string hex, string binary) ComputeSha256(string text)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(text ?? string.Empty);
            byte[] hashBytes = SHA256.HashData(inputBytes);

            string hex = Convert.ToHexString(hashBytes);

            var binSb = new StringBuilder(256);
            foreach (byte b in hashBytes)
            {
                binSb.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
            }

            return (hashBytes, hex, binSb.ToString());
        }

        /// <summary>
        /// Phân tích hiệu ứng thác đổ (Avalanche Effect) giữa hai văn bản đầu vào Input A và Input B.
        /// </summary>
        public AvalancheAnalysisResult AnalyzeAvalanche(string textA, string textB)
        {
            var (bytesA, hexA, binA) = ComputeSha256(textA);
            var (bytesB, hexB, binB) = ComputeSha256(textB);

            // 1. Đếm khác biệt ở đầu vào
            byte[] rawA = Encoding.UTF8.GetBytes(textA);
            byte[] rawB = Encoding.UTF8.GetBytes(textB);

            int charDiff = Math.Abs(textA.Length - textB.Length);
            int minLen = Math.Min(textA.Length, textB.Length);
            for (int i = 0; i < minLen; i++)
            {
                if (textA[i] != textB[i]) charDiff++;
            }

            int inputBitDiff = 0;
            int minRawLen = Math.Min(rawA.Length, rawB.Length);
            for (int i = 0; i < minRawLen; i++)
            {
                inputBitDiff += System.Numerics.BitOperations.PopCount((uint)(rawA[i] ^ rawB[i]));
            }
            inputBitDiff += Math.Abs(rawA.Length - rawB.Length) * 8;

            // 2. Tính khoảng cách Hamming trên 256 bit đầu ra (Hamming Distance)
            int flippedBits = 0;
            var differingBitIndices = new List<int>();
            for (int i = 0; i < 256; i++)
            {
                if (binA[i] != binB[i])
                {
                    flippedBits++;
                    differingBitIndices.Add(i);
                }
            }

            // 3. Khác biệt trên 64 ký tự Hex
            var differingHexIndices = new List<int>();
            for (int i = 0; i < 64; i++)
            {
                if (hexA[i] != hexB[i])
                {
                    differingHexIndices.Add(i);
                }
            }

            double percent = (flippedBits / 256.0) * 100.0;

            string conclusion = 
                $"ĐÁNH GIÁ HIỆU ỨNG THÁC ĐỔ (AVALANCHE EFFECT):\n" +
                $"• Đầu vào thay đổi: {charDiff} ký tự ({inputBitDiff} bit khác nhau).\n" +
                $"• Đầu ra SHA-256 bị đảo: {flippedBits}/256 bit, tương đương {percent:F2}% (Kỳ vọng lý thuyết: ~50%).\n" +
                $"• Số ký tự Hex thay đổi: {differingHexIndices.Count}/64 ký tự.\n" +
                $"• NHẬN XÉT: Hàm băm SHA-256 thoả mãn hoàn hảo tiêu chuẩn thác đổ nghiêm ngặt (Strict Avalanche Criterion - SAC).\n" +
                $"  Nhờ cấu trúc 64 vòng lặp với các phép toán phi tuyến Ch, Maj, Sigma và cộng modulo 2^32,\n" +
                $"  chỉ 1 bit thay đổi nhỏ ở đầu vào đã lan toả theo cấp số nhân, khiến giá trị băm đầu ra đảo xấp xỉ một nửa số bit.";

            return new AvalancheAnalysisResult
            {
                InputA = textA,
                InputB = textB,
                InputCharDiff = charDiff,
                InputBitDiff = inputBitDiff,
                HashA_Hex = hexA,
                HashB_Hex = hexB,
                HashA_Binary = binA,
                HashB_Binary = binB,
                FlippedBitsCount = flippedBits,
                FlippedBitsPercent = percent,
                DifferingBitIndices = differingBitIndices.ToArray(),
                DifferingHexIndices = differingHexIndices.ToArray(),
                AvalancheConclusion = conclusion
            };
        }

        #endregion

        #region TAB 4: DIGITAL SIGNATURE (DETERMINISTIC VS PROBABILISTIC / NONCE)

        /// <summary>
        /// Ký số RSA tiêu chuẩn định tính (Deterministic PKCS#1 v1.5).
        /// Với cùng 1 dữ liệu và cùng 1 Private Key, kết quả chữ ký luôn GIỐNG HỆT NHAU 100%.
        /// </summary>
        public byte[] SignPkcs1(byte[] data, RSA rsa)
        {
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Xác thực chữ ký số RSA tiêu chuẩn định tính (PKCS#1 v1.5).
        /// </summary>
        public bool VerifyPkcs1(byte[] data, byte[] signature, RSA rsa)
        {
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// PHƯƠNG PHÁP 1: Chữ ký số xác suất RSA-PSS (Probabilistic Signature Scheme - RFC 3447 / PKCS#1 v2.1).
        /// Tự động sinh chuỗi Salt ngẫu nhiên (32 bytes) trước khi ký.
        /// CÙNG 1 DỮ LIỆU + CÙNG 1 KHOÁ => MỖI LẦN KÝ TẠO RA CHỮ KÝ HOÀN TOÀN KHÁC NHAU,
        /// nhưng người nhận dùng Public Key vẫn xác thực thành công mà không cần truyền riêng Salt!
        /// </summary>
        public byte[] SignPss(byte[] data, RSA rsa)
        {
            return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        /// <summary>
        /// Xác thực chữ ký số RSA-PSS bằng Public Key.
        /// Thuật toán tự giải mã qua mặt nạ MGF1, bóc tách Salt và kiểm tra tính toàn vẹn.
        /// </summary>
        public bool VerifyPss(byte[] data, byte[] signature, RSA rsa)
        {
            return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        }

        /// <summary>
        /// PHƯƠNG PHÁP 2: Bổ sung Timestamp và Nonce (Số ngẫu nhiên dùng một lần) ở cấp độ gói tin ứng dụng.
        /// Chuỗi băm được tạo từ: SHA256(Data || Timestamp || Nonce).
        /// Mỗi lần bấm ký, Timestamp và Nonce thay đổi khiến dữ liệu ký thay đổi, tạo ra chữ ký khác nhau.
        /// </summary>
        public TimestampNonceSignedPackage CreateTimestampNoncePackage(string data, RSA rsa)
        {
            var now = DateTime.UtcNow;
            long ticks = now.Ticks;
            byte[] nonceBytes = new byte[16];
            RandomNumberGenerator.Fill(nonceBytes);
            string nonceHex = Convert.ToHexString(nonceBytes);

            // Cấu trúc gói tin payload
            string payload = $"{data}|{ticks}|{nonceHex}";
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

            byte[] signatureBytes = rsa.SignData(payloadBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            return new TimestampNonceSignedPackage
            {
                OriginalData = data,
                TimestampUtcTicks = ticks,
                TimestampUtc = now,
                NonceHex = nonceHex,
                PayloadToSign = payload,
                SignatureBase64 = Convert.ToBase64String(signatureBytes),
                HashAlgorithm = "SHA-256"
            };
        }

        /// <summary>
        /// Xác thực gói chữ ký kèm Timestamp và Nonce.
        /// Tái dựng lại Payload gốc và kiểm tra chữ ký qua Public Key.
        /// </summary>
        public bool VerifyTimestampNoncePackage(TimestampNonceSignedPackage package, RSA rsa)
        {
            string payload = $"{package.OriginalData}|{package.TimestampUtcTicks}|{package.NonceHex}";
            byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);
            byte[] sigBytes = Convert.FromBase64String(package.SignatureBase64);

            return rsa.VerifyData(payloadBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        #endregion
    }
}
