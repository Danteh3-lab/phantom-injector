using System.Buffers.Binary;
using System.Text;

namespace Phantom.Core.Stealth;

public enum ScramblePreset
{
    None,
    Basic,
    Standard,
    Extreme
}

/// <summary>
/// Produces a mutated copy of a DLL on disk. Mutations change cosmetic and
/// structural metadata so naive signature/hash detections fail. The original
/// file is never modified.
/// </summary>
public static class Scrambler
{
    public static string Scramble(string sourcePath, ScramblePreset preset)
    {
        if (preset == ScramblePreset.None)
            return sourcePath;

        var bytes = File.ReadAllBytes(sourcePath);
        if (bytes.Length < 0x40 || BinaryPrimitives.ReadUInt16LittleEndian(bytes) != 0x5A4D)
            throw new BadImageFormatException("Not a valid PE image.");

        var lfanew = (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0x3C));
        var signature = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(lfanew));
        if (signature != 0x00004550)
            throw new BadImageFormatException("Missing PE signature.");

        var fileHeader = lfanew + 4;
        var numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(fileHeader + 2));
        var sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(fileHeader + 16));
        var optional = fileHeader + 20;
        var is64 = BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(optional)) == 0x20B;
        var sectionStart = optional + sizeOfOptionalHeader;

        // Randomize the compile timestamp (Basic and above).
        RandomizeTimestamp(bytes, fileHeader);

        // Randomize section names (Basic and above).
        if (preset >= ScramblePreset.Basic)
            RandomizeSectionNames(bytes, sectionStart, numberOfSections);

        if (preset >= ScramblePreset.Standard)
        {
            StripRichHeader(bytes, lfanew);
            StripDebugDirectory(bytes, optional, is64);
            zeroChecksum(bytes, optional, is64);
        }

        if (preset >= ScramblePreset.Extreme)
        {
            MutateSectionCharacteristics(bytes, sectionStart, numberOfSections);
            RandomizeDosStub(bytes, lfanew);
        }

        var output = Path.Combine(Path.GetTempPath(),
            $"ph_{Guid.NewGuid():N}.dll");
        File.WriteAllBytes(output, bytes);
        return output;
    }

    private static void RandomizeTimestamp(byte[] bytes, int fileHeader)
    {
        var stamp = (uint)Random.Shared.NextInt64(0, uint.MaxValue);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(fileHeader + 4), stamp);
    }

    private static void RandomizeSectionNames(byte[] bytes, int sectionStart, int count)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (var i = 0; i < count; i++)
        {
            var off = sectionStart + i * 40;
            if (off + 8 > bytes.Length)
                break;

            for (var j = 0; j < 8; j++)
                bytes[off + j] = 0;
            var len = Random.Shared.Next(5, 9);
            for (var j = 0; j < len; j++)
                bytes[off + j] = (byte)alphabet[Random.Shared.Next(alphabet.Length)];
        }
    }

    private static void StripRichHeader(byte[] bytes, int lfanew)
    {
        // The Rich header sits between the DOS stub and the PE header,
        // delimited by "DanS" and "Rich".
        var richIndex = FindBytes(bytes, "Rich", 0x40, Math.Min(lfanew, bytes.Length));
        if (richIndex < 0)
            return;

        var dansIndex = FindBytes(bytes, "DanS", 0x40, richIndex);
        var start = dansIndex >= 0 ? dansIndex : 0x40;
        for (var i = start; i < richIndex + 4 && i < bytes.Length; i++)
            bytes[i] = 0;
    }

    private static int FindBytes(byte[] haystack, string needle, int start, int end)
    {
        var pattern = Encoding.ASCII.GetBytes(needle);
        for (var i = start; i <= end - pattern.Length && i < haystack.Length; i++)
        {
            var match = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (haystack[i + j] != pattern[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
                return i;
        }

        return -1;
    }

    private static void StripDebugDirectory(byte[] bytes, int optional, bool is64)
    {
        // Data directory array; index 6 is the debug directory.
        var dataDirOffset = optional + (is64 ? 112 : 96);
        var dirOffset = dataDirOffset + 6 * 8;
        if (dirOffset + 8 > bytes.Length)
            return;

        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(dirOffset), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(dirOffset + 4), 0);
    }

    private static void zeroChecksum(byte[] bytes, int optional, bool is64)
    {
        var checksumOffset = optional + 64;
        if (checksumOffset + 4 <= bytes.Length)
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(checksumOffset), 0);
    }

    private static void MutateSectionCharacteristics(byte[] bytes, int sectionStart, int count)
    {
        const uint imageScnMemDiscardable = 0x02000000;
        for (var i = 0; i < count; i++)
        {
            var off = sectionStart + i * 40;
            if (off + 40 > bytes.Length)
                break;

            var characteristics = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(off + 36));
            characteristics &= ~imageScnMemDiscardable;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(off + 36), characteristics);
        }
    }

    private static void RandomizeDosStub(byte[] bytes, int lfanew)
    {
        // The DOS stub lives between the DOS header (ends at 0x40) and the PE
        // header. The loader ignores it, so it is safe to scramble.
        var start = 0x40;
        var end = Math.Min(lfanew, bytes.Length);
        for (var i = start; i < end; i++)
            bytes[i] = (byte)Random.Shared.Next(1, 256);
    }
}
