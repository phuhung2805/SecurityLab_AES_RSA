using System;
using System.Collections.Generic;
using System.Text;
using SecurityLab_AES_RSA.Models;

namespace SecurityLab_AES_RSA.Services
{
    /// <summary>
    /// Dịch vụ phân tích cấu trúc file PEM và giải mã cây ASN.1 DER (TLV: Tag - Length - Value).
    /// Giúp sinh viên và chuyên gia an toàn thông tin quan sát trực quan từng byte và ý nghĩa toán học.
    /// </summary>
    public class PemParserService
    {
        /// <summary>
        /// Tách phần Header, Footer và giải mã phần thân Base64 ra mảng byte ASN.1 DER.
        /// </summary>
        public byte[] ExtractDerBytesFromPem(string pemText, out string header, out string footer)
        {
            header = string.Empty;
            footer = string.Empty;

            var lines = pemText.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            var base64Sb = new StringBuilder();

            foreach (var rawLine in lines)
            {
                string line = rawLine.Trim();
                if (line.StartsWith("-----BEGIN") && line.EndsWith("-----"))
                {
                    header = line;
                }
                else if (line.StartsWith("-----END") && line.EndsWith("-----"))
                {
                    footer = line;
                }
                else if (!string.IsNullOrWhiteSpace(line))
                {
                    base64Sb.Append(line);
                }
            }

            if (base64Sb.Length == 0)
            {
                throw new FormatException("Không tìm thấy dữ liệu Base64 hợp lệ trong file PEM.");
            }

            return Convert.FromBase64String(base64Sb.ToString());
        }

        /// <summary>
        /// Tạo bảng hiển thị Hex Dump chuẩn từ mảng byte (16 bytes mỗi dòng kèm cột ASCII).
        /// </summary>
        public string GenerateHexDump(byte[] data, int maxBytes = 4096)
        {
            if (data == null || data.Length == 0) return string.Empty;

            var sb = new StringBuilder();
            int bytesToShow = Math.Min(data.Length, maxBytes);

            for (int i = 0; i < bytesToShow; i += 16)
            {
                // Cột Offset (Địa chỉ byte)
                sb.AppendFormat("{0:X8}: ", i);

                // Cột Hex (16 bytes)
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < bytesToShow)
                    {
                        sb.AppendFormat("{0:X2} ", data[i + j]);
                    }
                    else
                    {
                        sb.Append("   ");
                    }
                    if (j == 7) sb.Append(" ");
                }

                sb.Append(" | ");

                // Cột ASCII giải nghĩa
                for (int j = 0; j < 16 && (i + j) < bytesToShow; j++)
                {
                    byte b = data[i + j];
                    char c = (b >= 32 && b <= 126) ? (char)b : '.';
                    sb.Append(c);
                }

                sb.AppendLine();
            }

            if (data.Length > maxBytes)
            {
                sb.AppendLine($"... [Còn {data.Length - maxBytes} bytes phía sau đã được rút gọn để giao diện mượt mà]");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Phân tích cấu trúc cây ASN.1 DER (Tag, Length, Value) của khoá RSA.
        /// </summary>
        public List<Asn1NodeInfo> ParseAsn1Structure(byte[] derBytes, string header)
        {
            var nodes = new List<Asn1NodeInfo>();
            if (derBytes == null || derBytes.Length == 0) return nodes;

            bool isRsaPrivateKeyPkcs1 = header.Contains("RSA PRIVATE KEY");
            bool isRsaPublicKeyPkcs1 = header.Contains("RSA PUBLIC KEY");
            bool isPkcs8PrivateKey = header.Contains("PRIVATE KEY") && !isRsaPrivateKeyPkcs1;
            bool isSpkiPublicKey = header.Contains("PUBLIC KEY") && !isRsaPublicKeyPkcs1;

            int offset = 0;

            // Xử lý các dạng bọc ngoài (PKCS#8 hoặc X.509 SubjectPublicKeyInfo)
            if (isPkcs8PrivateKey)
            {
                ParsePkcs8Wrapper(derBytes, ref offset, nodes);
            }
            else if (isSpkiPublicKey)
            {
                ParseSpkiWrapper(derBytes, ref offset, nodes);
            }
            else if (isRsaPrivateKeyPkcs1)
            {
                ParsePkcs1PrivateKeySequence(derBytes, offset, derBytes.Length, nodes);
            }
            else if (isRsaPublicKeyPkcs1)
            {
                ParsePkcs1PublicKeySequence(derBytes, offset, derBytes.Length, nodes);
            }
            else
            {
                // Cố gắng tự động nhận diện nếu header không rõ ràng
                GenericDerParser(derBytes, offset, derBytes.Length, 0, nodes);
            }

            return nodes;
        }

        private void ParsePkcs1PrivateKeySequence(byte[] data, int startOffset, int length, List<Asn1NodeInfo> nodes)
        {
            int cur = startOffset;
            if (cur >= data.Length || data[cur] != 0x30) return;

            ReadTlvHeader(data, cur, out int tagOffset, out byte tag, out int len, out int headerLen);

            nodes.Add(new Asn1NodeInfo
            {
                Offset = tagOffset,
                TagHex = $"0x{tag:X2}",
                TagName = "SEQUENCE",
                Length = len,
                FieldName = "RSAPrivateKey (SEQUENCE)",
                ValuePreview = $"{len} bytes",
                Explanation = "Cấu trúc cha bọc toàn bộ 9 tham số toán học của khoá RSA Private Key (RFC 3447 PKCS#1 v2.2)."
            });

            cur += headerLen;
            int end = cur + len;

            string[] fieldNames = {
                "version",
                "modulus (n)",
                "publicExponent (e)",
                "privateExponent (d)",
                "prime1 (p)",
                "prime2 (q)",
                "exponent1 (dp = d mod (p-1))",
                "exponent2 (dq = d mod (q-1))",
                "coefficient (q^-1 mod p)"
            };

            string[] explanations = {
                "Phiên bản PKCS#1 (thường là 0 cho khoá RSA hai số nguyên tố).",
                "Modulus công khai n = p * q. Đây là tích số lớn làm nền tảng cho không gian modulo của RSA.",
                "Số mũ công khai e (thường là 65537 = 0x010001 để tối ưu hoá tốc độ mã hoá).",
                "Số mũ bí mật d = e^-1 mod phi(n). Dùng để giải mã và tạo chữ ký số.",
                "Số nguyên tố bí mật thứ nhất p. Cần bảo mật tuyệt đối.",
                "Số nguyên tố bí mật thứ hai q. Cần bảo mật tuyệt đối.",
                "Số mũ giảm trừ theo định lý phần dư Trung Hoa (CRT): dp = d mod (p-1). Giúp tăng tốc giải mã.",
                "Số mũ giảm trừ CRT thứ hai: dq = d mod (q-1).",
                "Nghịch đảo CRT: qInv = q^-1 mod p. Dùng để kết hợp kết quả từ hai nửa CRT."
            };

            int fieldIndex = 0;
            while (cur < end && cur < data.Length)
            {
                ReadTlvHeader(data, cur, out int itemTagOffset, out byte itemTag, out int itemLen, out int itemHeaderLen);
                int valOffset = cur + itemHeaderLen;

                string field = fieldIndex < fieldNames.Length ? fieldNames[fieldIndex] : $"Extra Field #{fieldIndex}";
                string expl = fieldIndex < explanations.Length ? explanations[fieldIndex] : "Tham số mở rộng ASN.1";

                string preview = FormatValuePreview(data, valOffset, itemLen);

                nodes.Add(new Asn1NodeInfo
                {
                    Offset = itemTagOffset,
                    TagHex = $"0x{itemTag:X2}",
                    TagName = itemTag == 0x02 ? "INTEGER" : $"TAG(0x{itemTag:X2})",
                    Length = itemLen,
                    FieldName = field,
                    ValuePreview = preview,
                    Explanation = expl
                });

                cur += itemHeaderLen + itemLen;
                fieldIndex++;
            }
        }

        private void ParsePkcs1PublicKeySequence(byte[] data, int startOffset, int length, List<Asn1NodeInfo> nodes)
        {
            int cur = startOffset;
            if (cur >= data.Length || data[cur] != 0x30) return;

            ReadTlvHeader(data, cur, out int tagOffset, out byte tag, out int len, out int headerLen);

            nodes.Add(new Asn1NodeInfo
            {
                Offset = tagOffset,
                TagHex = $"0x{tag:X2}",
                TagName = "SEQUENCE",
                Length = len,
                FieldName = "RSAPublicKey (SEQUENCE)",
                ValuePreview = $"{len} bytes",
                Explanation = "Cấu trúc cha chứa 2 tham số công khai của khoá RSA: Modulus (n) và Public Exponent (e)."
            });

            cur += headerLen;
            int end = cur + len;

            string[] fieldNames = { "modulus (n)", "publicExponent (e)" };
            string[] explanations = {
                "Modulus công khai n = p * q. Dùng để mã hoá dữ liệu hoặc xác thực chữ ký.",
                "Số mũ công khai e (thường là 65537)."
            };

            int fieldIndex = 0;
            while (cur < end && cur < data.Length)
            {
                ReadTlvHeader(data, cur, out int itemTagOffset, out byte itemTag, out int itemLen, out int itemHeaderLen);
                int valOffset = cur + itemHeaderLen;

                string field = fieldIndex < fieldNames.Length ? fieldNames[fieldIndex] : $"Field #{fieldIndex}";
                string expl = fieldIndex < explanations.Length ? explanations[fieldIndex] : "Tham số ASN.1";

                nodes.Add(new Asn1NodeInfo
                {
                    Offset = itemTagOffset,
                    TagHex = $"0x{itemTag:X2}",
                    TagName = itemTag == 0x02 ? "INTEGER" : $"TAG(0x{itemTag:X2})",
                    Length = itemLen,
                    FieldName = field,
                    ValuePreview = FormatValuePreview(data, valOffset, itemLen),
                    Explanation = expl
                });

                cur += itemHeaderLen + itemLen;
                fieldIndex++;
            }
        }

        private void ParsePkcs8Wrapper(byte[] data, ref int offset, List<Asn1NodeInfo> nodes)
        {
            ReadTlvHeader(data, offset, out int outerTagOff, out byte outerTag, out int outerLen, out int outerHdrLen);
            nodes.Add(new Asn1NodeInfo
            {
                Offset = outerTagOff,
                TagHex = $"0x{outerTag:X2}",
                TagName = "SEQUENCE",
                Length = outerLen,
                FieldName = "PrivateKeyInfo (PKCS#8)",
                ValuePreview = $"{outerLen} bytes",
                Explanation = "Định dạng bao bọc khoá riêng tư tiêu chuẩn PKCS#8 (RFC 5208) hỗ trợ nhiều thuật toán mật mã."
            });

            int cur = offset + outerHdrLen;
            int end = cur + outerLen;

            // 1. Version
            if (cur < end && data[cur] == 0x02)
            {
                ReadTlvHeader(data, cur, out int vOff, out byte vTag, out int vLen, out int vHdr);
                nodes.Add(new Asn1NodeInfo
                {
                    Offset = vOff,
                    TagHex = $"0x{vTag:X2}",
                    TagName = "INTEGER",
                    Length = vLen,
                    FieldName = "version",
                    ValuePreview = FormatValuePreview(data, cur + vHdr, vLen),
                    Explanation = "Phiên bản cấu trúc PKCS#8 (0 = v1)."
                });
                cur += vHdr + vLen;
            }

            // 2. AlgorithmIdentifier (SEQUENCE)
            if (cur < end && data[cur] == 0x30)
            {
                ReadTlvHeader(data, cur, out int aOff, out byte aTag, out int aLen, out int aHdr);
                nodes.Add(new Asn1NodeInfo
                {
                    Offset = aOff,
                    TagHex = $"0x{aTag:X2}",
                    TagName = "SEQUENCE",
                    Length = aLen,
                    FieldName = "privateKeyAlgorithm",
                    ValuePreview = "rsaEncryption (OID: 1.2.840.113549.1.1.1)",
                    Explanation = "Xác định thuật toán mật mã là RSA (1.2.840.113549.1.1.1) kèm tham số NULL."
                });
                cur += aHdr + aLen;
            }

            // 3. OCTET STRING chứa cấu trúc PKCS#1 RSAPrivateKey thực sự
            if (cur < end && data[cur] == 0x04)
            {
                ReadTlvHeader(data, cur, out int oOff, out byte oTag, out int oLen, out int oHdr);
                nodes.Add(new Asn1NodeInfo
                {
                    Offset = oOff,
                    TagHex = $"0x{oTag:X2}",
                    TagName = "OCTET STRING",
                    Length = oLen,
                    FieldName = "privateKey (Raw Octets)",
                    ValuePreview = $"Chứa mảng byte DER PKCS#1 ({oLen} bytes)",
                    Explanation = "Chuỗi byte nhị phân gói bên trong chính là cấu trúc RSAPrivateKey chuẩn PKCS#1."
                });

                // Phân tích sâu vào cấu trúc PKCS#1 bên trong OCTET STRING
                ParsePkcs1PrivateKeySequence(data, cur + oHdr, oLen, nodes);
            }
        }

        private void ParseSpkiWrapper(byte[] data, ref int offset, List<Asn1NodeInfo> nodes)
        {
            ReadTlvHeader(data, offset, out int outerTagOff, out byte outerTag, out int outerLen, out int outerHdrLen);
            nodes.Add(new Asn1NodeInfo
            {
                Offset = outerTagOff,
                TagHex = $"0x{outerTag:X2}",
                TagName = "SEQUENCE",
                Length = outerLen,
                FieldName = "SubjectPublicKeyInfo (X.509 SPKI)",
                ValuePreview = $"{outerLen} bytes",
                Explanation = "Cấu trúc bao bọc khoá công khai X.509 SPKI (RFC 5280) tiêu chuẩn của chứng thực số."
            });

            int cur = offset + outerHdrLen;
            int end = cur + outerLen;

            // 1. AlgorithmIdentifier (SEQUENCE)
            if (cur < end && data[cur] == 0x30)
            {
                ReadTlvHeader(data, cur, out int aOff, out byte aTag, out int aLen, out int aHdr);
                nodes.Add(new Asn1NodeInfo
                {
                    Offset = aOff,
                    TagHex = $"0x{aTag:X2}",
                    TagName = "SEQUENCE",
                    Length = aLen,
                    FieldName = "algorithmIdentifier",
                    ValuePreview = "rsaEncryption (OID: 1.2.840.113549.1.1.1)",
                    Explanation = "Định danh thuật toán khoá công khai là RSA."
                });
                cur += aHdr + aLen;
            }

            // 2. BIT STRING chứa PKCS#1 RSAPublicKey
            if (cur < end && data[cur] == 0x03)
            {
                ReadTlvHeader(data, cur, out int bOff, out byte bTag, out int bLen, out int bHdr);
                nodes.Add(new Asn1NodeInfo
                {
                    Offset = bOff,
                    TagHex = $"0x{bTag:X2}",
                    TagName = "BIT STRING",
                    Length = bLen,
                    FieldName = "subjectPublicKey",
                    ValuePreview = $"Gói RSAPublicKey ({bLen} bytes)",
                    Explanation = "Chuỗi bit chứa 1 byte padding (0x00 unused bits) và tiếp nối là cấu trúc RSAPublicKey PKCS#1."
                });

                // Nhảy qua 1 byte unused bits (thường là 0x00)
                int innerStart = cur + bHdr + 1;
                int innerLen = bLen - 1;
                ParsePkcs1PublicKeySequence(data, innerStart, innerLen, nodes);
            }
        }

        private void GenericDerParser(byte[] data, int offset, int length, int depth, List<Asn1NodeInfo> nodes)
        {
            int cur = offset;
            int end = offset + length;

            while (cur < end && cur < data.Length)
            {
                ReadTlvHeader(data, cur, out int tagOff, out byte tag, out int len, out int hdrLen);
                int valOff = cur + hdrLen;

                string tagName = tag switch
                {
                    0x30 => "SEQUENCE",
                    0x02 => "INTEGER",
                    0x03 => "BIT STRING",
                    0x04 => "OCTET STRING",
                    0x05 => "NULL",
                    0x06 => "OBJECT IDENTIFIER",
                    _ => $"TAG(0x{tag:X2})"
                };

                nodes.Add(new Asn1NodeInfo
                {
                    Offset = tagOff,
                    TagHex = $"0x{tag:X2}",
                    TagName = tagName,
                    Length = len,
                    FieldName = $"ASN.1 Depth {depth} [{tagName}]",
                    ValuePreview = FormatValuePreview(data, valOff, len),
                    Explanation = $"Phần tử ASN.1 DER tại vị trí offset {tagOff}."
                });

                if (tag == 0x30 && depth < 3)
                {
                    GenericDerParser(data, valOff, len, depth + 1, nodes);
                }

                cur += hdrLen + len;
            }
        }

        private static void ReadTlvHeader(byte[] data, int offset, out int tagOffset, out byte tag, out int length, out int headerLength)
        {
            tagOffset = offset;
            tag = data[offset];
            byte lenByte = data[offset + 1];

            if ((lenByte & 0x80) == 0)
            {
                // Độ dài ngắn (0 - 127 bytes)
                length = lenByte;
                headerLength = 2; // 1 byte tag + 1 byte length
            }
            else
            {
                // Độ dài dài (> 127 bytes)
                int numLenBytes = lenByte & 0x7F;
                int val = 0;
                for (int i = 0; i < numLenBytes; i++)
                {
                    val = (val << 8) | data[offset + 2 + i];
                }
                length = val;
                headerLength = 2 + numLenBytes;
            }
        }

        private static string FormatValuePreview(byte[] data, int offset, int length)
        {
            if (length <= 0 || offset >= data.Length) return "(empty)";
            int previewLen = Math.Min(length, 16);
            int actualLen = Math.Min(previewLen, data.Length - offset);

            var sb = new StringBuilder();
            for (int i = 0; i < actualLen; i++)
            {
                sb.AppendFormat("{0:X2} ", data[offset + i]);
            }

            if (length > previewLen)
            {
                sb.Append($"... ({length} bytes)");
            }

            return sb.ToString().Trim();
        }
    }
}
