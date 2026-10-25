using System;

namespace SecurityLab_AES_RSA.Models
{
    /// <summary>
    /// Chứa thông tin khoá AES và Vector khởi tạo (IV).
    /// </summary>
    public class AesKeyBundle
    {
        public int KeySizeBits { get; set; } = 256;
        public string KeyBase64 { get; set; } = string.Empty;
        public string KeyHex { get; set; } = string.Empty;
        public string IvBase64 { get; set; } = string.Empty;
        public string IvHex { get; set; } = string.Empty;
        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

        public byte[] GetKeyBytes() => Convert.FromBase64String(KeyBase64);
        public byte[] GetIvBytes() => Convert.FromBase64String(IvBase64);
    }

    /// <summary>
    /// Kết quả đo hiệu năng mã hoá / giải mã file.
    /// </summary>
    public class FileCryptoResult
    {
        public bool Success { get; set; }
        public string FilePath { get; set; } = string.Empty;
        public long FileSizeBytes { get; set; }
        public TimeSpan Elapsed { get; set; }
        public double SpeedMBps { get; set; }
        public string Sha256Hash { get; set; } = string.Empty;
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Kết quả so sánh từng byte giữa 2 file (file gốc vs file sau giải mã).
    /// </summary>
    public class FileCompareResult
    {
        public bool AreIdentical { get; set; }
        public long TotalBytesCompared { get; set; }
        public long MismatchCount { get; set; }
        public long FirstMismatchOffset { get; set; } = -1;
        public string Sha256Source { get; set; } = string.Empty;
        public string Sha256Decrypted { get; set; } = string.Empty;
        public TimeSpan Elapsed { get; set; }
        public string Conclusion { get; set; } = string.Empty;
    }

    /// <summary>
    /// Cấu trúc phân tích từng node trong cây ASN.1 DER của file PEM.
    /// </summary>
    public class Asn1NodeInfo
    {
        public int Offset { get; set; }
        public string TagHex { get; set; } = string.Empty;
        public string TagName { get; set; } = string.Empty;
        public int Length { get; set; }
        public string FieldName { get; set; } = string.Empty;
        public string ValuePreview { get; set; } = string.Empty;
        public string Explanation { get; set; } = string.Empty;
    }

    /// <summary>
    /// Tham số toán học trích xuất từ RSA Key (Public / Private).
    /// </summary>
    public class ExtractedRsaParams
    {
        public bool IsPrivateKey { get; set; }
        public int KeySizeBits { get; set; }
        public string ModulusN_Hex { get; set; } = string.Empty;
        public string ModulusN_Base64 { get; set; } = string.Empty;
        public int ModulusBytes { get; set; }
        public string PublicExponentE_Hex { get; set; } = string.Empty;
        public long PublicExponentE_Decimal { get; set; }
        
        // Các tham số dành riêng cho Private Key
        public string? PrivateExponentD_Hex { get; set; }
        public int? PrivateExponentD_Bytes { get; set; }
        public string? PrimeP_Hex { get; set; }
        public string? PrimeQ_Hex { get; set; }
        public string? ExponentDP_Hex { get; set; }
        public string? ExponentDQ_Hex { get; set; }
        public string? InverseQ_Hex { get; set; }
    }

    /// <summary>
    /// Kết quả benchmark đo tốc độ Public Key vs Private Key.
    /// </summary>
    public class RsaBenchmarkResult
    {
        public int Iterations { get; set; }
        public TimeSpan TotalPublicKeyTime { get; set; }
        public double AvgPublicKeyMs { get; set; }
        public double PublicKeyOpsPerSec { get; set; }

        public TimeSpan TotalPrivateKeyTime { get; set; }
        public double AvgPrivateKeyMs { get; set; }
        public double PrivateKeyOpsPerSec { get; set; }

        public double SpeedRatio { get; set; }
        public string MathematicalExplanation { get; set; } = string.Empty;
    }

    /// <summary>
    /// Kết quả phân tích hiệu ứng thác đổ (Avalanche Effect) của hàm băm SHA-256.
    /// </summary>
    public class AvalancheAnalysisResult
    {
        public string InputA { get; set; } = string.Empty;
        public string InputB { get; set; } = string.Empty;
        public int InputCharDiff { get; set; }
        public int InputBitDiff { get; set; }

        public string HashA_Hex { get; set; } = string.Empty;
        public string HashB_Hex { get; set; } = string.Empty;

        public string HashA_Binary { get; set; } = string.Empty;
        public string HashB_Binary { get; set; } = string.Empty;

        public int FlippedBitsCount { get; set; }
        public double FlippedBitsPercent { get; set; }
        public int TotalBits => 256;

        public int[] DifferingBitIndices { get; set; } = Array.Empty<int>();
        public int[] DifferingHexIndices { get; set; } = Array.Empty<int>();

        public string AvalancheConclusion { get; set; } = string.Empty;
    }

    /// <summary>
    /// Gói chữ ký số kèm Timestamp và Nonce (Phương pháp 2).
    /// </summary>
    public class TimestampNonceSignedPackage
    {
        public string OriginalData { get; set; } = string.Empty;
        public long TimestampUtcTicks { get; set; }
        public DateTime TimestampUtc { get; set; }
        public string NonceHex { get; set; } = string.Empty;
        public string PayloadToSign { get; set; } = string.Empty;
        public string SignatureBase64 { get; set; } = string.Empty;
        public string HashAlgorithm { get; set; } = "SHA-256";
    }
}
