using System.Buffers.Binary;

namespace Phantom.Core.Injection;

internal sealed class PeSection
{
    public string Name { get; init; } = string.Empty;
    public uint VirtualSize { get; init; }
    public uint VirtualAddress { get; init; }
    public uint SizeOfRawData { get; init; }
    public uint PointerToRawData { get; init; }
    public uint Characteristics { get; init; }
}

internal struct DataDirectory
{
    public uint VirtualAddress;
    public uint Size;
}

/// <summary>
/// Minimal PE64 (x64) parser. Throws <see cref="BadImageFormatException"/> for
/// non-64-bit images.
/// </summary>
internal sealed class PeImage
{
    public byte[] Raw { get; }
    public bool Is64Bit { get; }
    public ushort Machine { get; }
    public ulong ImageBase { get; }
    public uint SizeOfImage { get; }
    public uint SizeOfHeaders { get; }
    public uint AddressOfEntryPoint { get; }
    public uint SectionAlignment { get; }
    public uint FileAlignment { get; }
    public ushort NumberOfSections { get; }
    public PeSection[] Sections { get; }
    public DataDirectory[] Directories { get; }

    public const int DirectoryExport = 0;
    public const int DirectoryImport = 1;
    public const int DirectoryException = 3;
    public const int DirectoryBaseReloc = 5;
    public const int DirectoryTls = 9;

    public PeImage(byte[] raw)
    {
        Raw = raw;
        if (raw.Length < 0x40 || ReadU16(0) != 0x5A4D)
            throw new BadImageFormatException("Not a valid MZ image.");

        var lfanew = (int)ReadU32(0x3C);
        if (lfanew < 0 || (long)lfanew + 24 > raw.Length || ReadU32(lfanew) != 0x00004550)
            throw new BadImageFormatException("Missing or out-of-range PE signature.");

        var fileHeader = lfanew + 4;
        Machine = ReadU16(fileHeader);
        NumberOfSections = ReadU16(fileHeader + 2);
        var sizeOfOptionalHeader = ReadU16(fileHeader + 16);

        if (Machine != 0x8664)
            throw new BadImageFormatException("Only AMD64 (x64) images are supported.");

        var optional = fileHeader + 20;
        // The fixed IMAGE_OPTIONAL_HEADER64 portion is 112 bytes through
        // NumberOfRvaAndSizes; the directory-fit check below covers the rest.
        if (sizeOfOptionalHeader < 112 || (long)optional + sizeOfOptionalHeader > raw.Length)
            throw new BadImageFormatException("The optional header is missing or outside the file.");

        var magic = ReadU16(optional);
        Is64Bit = magic == 0x20B;
        if (!Is64Bit)
            throw new BadImageFormatException("Only 64-bit (PE32+) images are supported.");

        AddressOfEntryPoint = ReadU32(optional + 16);
        ImageBase = ReadU64(optional + 24);
        SectionAlignment = ReadU32(optional + 32);
        FileAlignment = ReadU32(optional + 36);
        SizeOfImage = ReadU32(optional + 56);
        SizeOfHeaders = ReadU32(optional + 60);

        if (SizeOfImage == 0 || SizeOfHeaders > SizeOfImage || SizeOfHeaders > raw.Length)
            throw new BadImageFormatException("The image size or header size is invalid.");
        if (AddressOfEntryPoint != 0 && AddressOfEntryPoint >= SizeOfImage)
            throw new BadImageFormatException("The entry point is outside the mapped image.");

        var numberOfRvaAndSizes = ReadU32(optional + 108);

        // Directories must fit inside the declared optional header.
        if (numberOfRvaAndSizes > 64 ||
            (long)112 + (long)numberOfRvaAndSizes * 8 > sizeOfOptionalHeader)
            throw new BadImageFormatException("The data directories exceed the optional header.");

        Directories = new DataDirectory[numberOfRvaAndSizes];
        for (var i = 0; i < numberOfRvaAndSizes; i++)
        {
            var off = optional + 112 + i * 8;
            Directories[i] = new DataDirectory { VirtualAddress = ReadU32(off), Size = ReadU32(off + 4) };
        }

        var sectionStart = optional + sizeOfOptionalHeader;
        if ((long)sectionStart + (long)NumberOfSections * 40 > raw.Length)
            throw new BadImageFormatException("The section table is outside the file.");

        Sections = new PeSection[NumberOfSections];
        for (var i = 0; i < NumberOfSections; i++)
        {
            var off = sectionStart + i * 40;
            var nameBytes = Raw.AsSpan(off, 8);
            var nullIdx = nameBytes.IndexOf((byte)0);
            var name = System.Text.Encoding.ASCII.GetString(nameBytes[..(nullIdx < 0 ? 8 : nullIdx)]);

            var virtualSize = ReadU32(off + 8);
            var virtualAddress = ReadU32(off + 12);
            var sizeOfRawData = ReadU32(off + 16);
            var pointerToRawData = ReadU32(off + 20);

            // Both the virtual and the raw extent must fit: BuildImage copies
            // SizeOfRawData bytes, and the loader maps max(VirtualSize, SizeOfRawData).
            var mappedSize = Math.Max(virtualSize, sizeOfRawData);
            if ((long)virtualAddress + mappedSize > SizeOfImage)
                throw new BadImageFormatException($"Section '{name}' extends past the mapped image.");
            if (sizeOfRawData > 0 && (long)pointerToRawData + sizeOfRawData > raw.Length)
                throw new BadImageFormatException($"Section '{name}' raw data extends past the file.");

            Sections[i] = new PeSection
            {
                Name = name,
                VirtualSize = virtualSize,
                VirtualAddress = virtualAddress,
                SizeOfRawData = sizeOfRawData,
                PointerToRawData = pointerToRawData,
                Characteristics = ReadU32(off + 36)
            };
        }
    }

    public DataDirectory Directory(int index)
        => index >= 0 && index < Directories.Length ? Directories[index] : default;

    public ushort ReadU16(int offset) => BinaryPrimitives.ReadUInt16LittleEndian(Raw.AsSpan(offset, 2));
    public uint ReadU32(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(Raw.AsSpan(offset, 4));
    public ulong ReadU64(int offset) => BinaryPrimitives.ReadUInt64LittleEndian(Raw.AsSpan(offset, 8));

    public static uint CharacteristicsToProtection(uint characteristics)
    {
        const uint imageScnMemExecute = 0x20000000;
        const uint imageScnMemRead = 0x40000000;
        const uint imageScnMemWrite = 0x80000000;

        var execute = (characteristics & imageScnMemExecute) != 0;
        var read = (characteristics & imageScnMemRead) != 0;
        var write = (characteristics & imageScnMemWrite) != 0;

        return (execute, read, write) switch
        {
            (true, _, true) => Native.NativeConstants.PAGE_EXECUTE_READWRITE,
            (true, true, false) => Native.NativeConstants.PAGE_EXECUTE_READ,
            (true, false, false) => Native.NativeConstants.PAGE_EXECUTE,
            (false, true, true) => Native.NativeConstants.PAGE_READWRITE,
            (false, true, false) => Native.NativeConstants.PAGE_READONLY,
            _ => Native.NativeConstants.PAGE_READONLY
        };
    }

    /// <summary>
    /// Resolves a file offset from an RVA using the section table. Headers use
    /// the raw offset directly.
    /// </summary>
    public int RvaToOffset(uint rva)
    {
        if (rva < SizeOfHeaders)
            return (int)rva;

        foreach (var s in Sections)
        {
            var size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && (ulong)rva < (ulong)s.VirtualAddress + size)
                return (int)(s.PointerToRawData + (rva - s.VirtualAddress));
        }

        return -1;
    }

    /// <summary>
    /// True when the RVA lies inside the mapped headers or a section, i.e. it is
    /// a valid code/data address in the loaded image.
    /// </summary>
    public bool IsRvaInImage(uint rva)
    {
        if (rva < SizeOfHeaders)
            return true;

        foreach (var s in Sections)
        {
            var size = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && (ulong)rva < (ulong)s.VirtualAddress + size)
                return true;
        }

        return false;
    }
}
