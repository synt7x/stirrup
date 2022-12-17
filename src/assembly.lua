local file
local options
local _ = 0
local lines = {}
local alignment

local function inc(v)
    _ = _ + v
end

local function writeln(line)
    table.insert(lines, line)
    return #lines
end

local function skipln(n)
    inc(n)
    return writeln('')
end

local function dw(value)
    writeln('dw ' .. value)
    inc(2)
end

local function dd(value)
    writeln('dd ' .. value)
    inc(4)
end

local function db(value)
    writeln('db ' .. value)
    inc(1)
end

local function asm(value)
    writeln(value)
    local whitespace = 0

    for i = 1, #value do
        if string.sub(value, i, i) == " " then
            whitespace = whitespace + 1
        end
    end

    inc(whitespace + 1)
end

local function dq(value)
    writeln('dq ' .. value)
    inc(8)
end

local function section_header(name, characteristics)
    writeln('dq \'' .. name .. '\'')
    inc(8)


    local VirtualSize = skipln(4)
    local VirtualAddress = skipln(4)
    local SizeOfRawData = skipln(4)
    local PointerToRawData = skipln(4)

    dd("0")
    dd("0")
    dw("0")
    dw("0")

    dd(characteristics)
    return VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
end

local function header()
    dw("'MZ'")
    writeln("db 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00")
    inc(126)
    writeln("db 'PE', 0, 0")
    inc(4)
    
    if options['-fwin32'] then
        writeln("dw 0x14c")
        inc(2)
    else
        writeln("dw 0x8664")
        inc(2)
    end

    dw("0x03") -- Number of Sections
    dd("0") -- Timestamp
    dd("0")
    dd("0")

    local OptionalHeaderSize = skipln(2)
    dw("0x0202")

    -- Optional Header Start
    local OptionalHeader = _

    dw("0x20b")
    db("0x02")
    db("0x20")

    local SizeOfCode = skipln(4)
    local SizeOfInitializedData = skipln(4)
    dd("0")
    local AddressOfEntryPoint = skipln(4)
    local BaseOfCode = skipln(4)
    local ImageBase = dq("0x400000")

    dd(alignment)
    dd(alignment)
    dw("0x4")
    dw("0")
    dw("0")
    dw("0")
    dw("0x5")
    dw("0x2")
    dd("0")
    
    local SizeOfImage = skipln(4)
    local SizeOfHeaders = skipln(4)
    dd("0")
    dw("0x3")
    dw("0")
    
    dq("0x200000")
    dq("0x1000")
    dq("0x100000")
    dq("0x1000")
    dd("0")

    local NumberOfRvaAndSizes = skipln(4)
    local DataDirectory = _

    dd("0")
    dd("0")

    local ImportData = skipln(4)
    local ImportSize = skipln(4)

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    dd("0")
    dd("0")
    
    dd("0")
    dd("0")

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    local IATData = skipln(4)
    local IATSize = skipln(4)

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    dd("0")
    dd("0")

    lines[NumberOfRvaAndSizes] = "dd " .. (_ - DataDirectory) / 8
    lines[OptionalHeaderSize] = "dw " .. _ - OptionalHeader

    local TextVirtualSize, TextVirtualAddress, TextSizeOfRawData, TextPointerToRawData = section_header(".text", '0x0000000060500060')
    local DataVirtualSize, DataVirtualAddress, DataSizeOfRawData, DataPointerToRawData = section_header(".data", '0x00000000c0600040')
    local IDataVirtualSize, IDataVirtualAddress, IDataSizeOfRawData, IDataPointerToRawData = section_header(".idata", '0x00000000c0300040')

    lines[TextPointerToRawData] = "dd " .. _
    lines[TextVirtualAddress] = lines[TextPointerToRawData]
    lines[SizeOfHeaders] = "dd " .. _

    local _TEXT = _
    local Entrypoint = _

    asm("xor rax, rax")
    asm("ret")

    lines[TextSizeOfRawData] = "dd " .. _ - Entrypoint
    lines[TextVirtualSize] = lines[TextSizeOfRawData]


    lines[DataPointerToRawData] = "dd " .. _
    lines[DataVirtualAddress] = lines[DataPointerToRawData]

    local _DATA = _
    local Kernel32 = _
    db("'KERNEL32.DLL', 0")
    inc(12)

    lines[DataSizeOfRawData] = "dd " .. _ - _DATA
    lines[DataVirtualSize] = lines[DataSizeOfRawData]

    lines[SizeOfInitializedData] = lines[DataSizeOfRawData]
    lines[SizeOfCode] = lines[TextSizeOfRawData]
    lines[BaseOfCode] = lines[TextVirtualAddress]
    lines[AddressOfEntryPoint] = lines[TextVirtualAddress]
    lines[ImportData] = "dd " .. _


    lines[IDataPointerToRawData] = "dd " .. _
    lines[IDataVirtualAddress] = lines[IDataPointerToRawData]

    lines[IATData] = "dd " .. _

    local _IDATA = _

    local Kern32_RVA = skipln(4)
    dd("0")
    dd("0")
    dd(Kernel32)
    local Kern32_Thunk = skipln(4)

    dd("0")
    dd("0")
    dd("0")
    dd("0")
    dd("0")

    lines[ImportSize] = "dd " .. _ - _IDATA
    lines[Kern32_RVA] = "dd " .. _
    lines[Kern32_Thunk] = "dd " .. _
    lines[IATSize] = "dd " .. _ - _IDATA

    local GetStdHandleLookup = skipln(8)
    local WriteFileLookup = skipln(8)
    dq("0")

    local HintTable = _

    lines[GetStdHandleLookup] = "dq " .. _

    dw("0")
    db("'GetStdHandle', 0")
    inc(12)
    db("0")

    lines[WriteFileLookup] = "dq " .. _

    dw("0")
    db("'WriteFile', 0")
    inc(9)

    
    lines[IDataSizeOfRawData] = "dd " .. _ - _IDATA
    lines[IDataVirtualSize] = lines[IDataSizeOfRawData]
    lines[SizeOfImage] = "dd " .. _

    while (_ % alignment) ~= 1 and (_ % alignment) ~= 0 do
        dw("0")
    end
end

return function(f, o, a)
    file = f
    options = o
    alignment = a

    f:writeln("BITS 64\n")

    header()

    for i, line in ipairs(lines) do
        f:write(line .. '\n')
    end
end