local file
local options
local _ = 0
local lines = {}
local alignment = 1

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

local function dw(n)
    n = (n < 0) and (4294967296 + n) or n
    writeln(
        string.reverse(
        string.char((math.modf(n/256))%256)
        .. string.char(n%256))
    )
    inc(2)
end

local function dd(n)
    n = (n < 0) and (4294967296 + n) or n
    writeln(
        string.reverse(
        string.char(math.modf(n/16777216)%256)
        .. string.char((math.modf(n/65536))%256)
        .. string.char((math.modf(n/256))%256)
        .. string.char(n%256))
    )
    inc(4)
end

local function db(value)
    writeln(string.char(value))
    inc(1)
end

local function rdw(n)
    n = (n < 0) and (4294967296 + n) or n
    return (
        string.reverse(
        string.char((math.modf(n/256))%256)
        .. string.char(n%256)
)
    )
end

local function rdd(n)
    n = (n < 0) and (4294967296 + n) or n
    return (
        string.reverse(string.char(
        math.modf(n/16777216)%256)
        .. string.char((math.modf(n/65536))%256)
        .. string.char((math.modf(n/256))%256)
        .. string.char(n%256))
    )
end

local function rdb(n)
    return string.char(value)
end

local function rdq(n)
    n = string.format("%x", n)
    local starting_byte = #n
    local bytes = ""

    n = string.reverse(n)
    for i = 1, starting_byte, 2 do
        local first = n:sub(i, i)
        local second = n:sub(i + 1, i + 1) or '0'
        bytes = bytes .. string.char(tonumber(second .. first, 16))
    end

    for i = 1, 8 - math.ceil(starting_byte / 2) do
        bytes = bytes .. string.char(0)
    end

    return bytes
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

function dq(n)
    local starting_byte = #n
    local bytes = ""

    n = string.reverse(n)
    for i = 1, starting_byte, 2 do
        local first = n:sub(i, i)
        local second = n:sub(i + 1, i + 1) or '0'
        bytes = bytes .. string.char(tonumber(second .. first, 16))
    end

    for i = 1, 8 - math.ceil(starting_byte / 2) do
        bytes = bytes .. string.char(0)
    end

    writeln(bytes)
    inc(8)
    return _ - 8
end


local function txt(value)
    writeln(value)
    inc(#value)
end

local function section_header(name, characteristics)
    txt(name)

    for i = 1, 8 - #name do
        db(0)
    end

    local VirtualSize = skipln(4)
    local VirtualAddress = skipln(4)
    local SizeOfRawData = skipln(4)
    local PointerToRawData = skipln(4)

    dd(0)
    dd(0)
    dw(0)
    dw(0)

    dd(characteristics)
    return VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData
end

local function header()
    txt("MZ")

    db(144)
    db(0)
    db(3)
    db(0)
    db(0)
    db(0)
    db(4)
    db(0)
    db(0)
    db(0)
    db(255)
    db(255)
    db(0)
    db(0)
    db(184)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(64)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(128)
    db(0)
    db(0)
    db(0)
    db(14)
    db(31)
    db(186)
    db(14)
    db(0)
    db(180)
    db(9)
    db(205)
    db(33)
    db(184)
    db(1)
    db(76)
    db(205)
    db(33)
    db(84)
    db(104)
    db(105)
    db(115)
    db(32)
    db(112)
    db(114)
    db(111)
    db(103)
    db(114)
    db(97)
    db(109)
    db(32)
    db(99)
    db(97)
    db(110)
    db(110)
    db(111)
    db(116)
    db(32)
    db(98)
    db(101)
    db(32)
    db(114)
    db(117)
    db(110)
    db(32)
    db(105)
    db(110)
    db(32)
    db(68)
    db(79)
    db(83)
    db(32)
    db(109)
    db(111)
    db(100)
    db(101)
    db(46)
    db(13)
    db(13)
    db(10)
    db(36)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)
    db(0)


    txt('PE')
    db(0)
    db(0)
    
    dw(0x8664)

    dw(0x03) -- Number of Sections
    dd(0) -- Timestamp
    dd(0)
    dd(0)

    local OptionalHeaderSize = skipln(2)
    dw(0x0202)

    -- Optional Header Start
    local OptionalHeader = _

    dw(0x20b)
    db(0x02)
    db(0x20)

    local SizeOfCode = skipln(4)
    local SizeOfInitializedData = skipln(4)
    dd(0)
    local AddressOfEntryPoint = skipln(4)
    local BaseOfCode = skipln(4)
    local ImageBase = dq("400000")

    dd(alignment)
    dd(alignment)
    dw(0x4) -- start line C0
    dw(0)
    dw(0)
    dw(0)
    dw(0x5)
    dw(0x2)
    dd(0)
    
    -- D0
    local SizeOfImage = skipln(4)
    local SizeOfHeaders = skipln(4)
    dd(0)
    dw(0x3)
    dw(0)
    
    -- E0
    dq("200000")
    dq("1000")
    -- F0

    dq("100000")
    dq("1000")

    -- 100
    dd(0)

    local NumberOfRvaAndSizes = skipln(4)
    local DataDirectory = _

    dd(0)
    dd(0)

    -- 110
    local ImportData = skipln(4)
    local ImportSize = skipln(4)

    dd(0)
    dd(0)

    -- 120
    dd(0)
    dd(0)

    dd(0)
    dd(0)

    -- 130
    dd(0)
    dd(0)

    dd(0)
    dd(0)
    
    -- 140
    dd(0)
    dd(0)

    dd(0)
    dd(0)

    -- 150
    dd(0)
    dd(0)

    dd(0)
    dd(0)

    -- 160
    dd(0)
    dd(0)

    local IATData = skipln(4)
    local IATSize = skipln(4)

    -- 170
    dd(0)
    dd(0)

    dd(0)
    dd(0)

    -- 180
    dd(0)
    dd(0)

    lines[NumberOfRvaAndSizes] = rdd((_ - DataDirectory) / 8)
    lines[OptionalHeaderSize] = rdw(_ - OptionalHeader)

    local TextVirtualSize, TextVirtualAddress, TextSizeOfRawData, TextPointerToRawData = section_header('.text', 0x0000000060500060)
    local DataVirtualSize, DataVirtualAddress, DataSizeOfRawData, DataPointerToRawData = section_header('.data', 0x00000000c0600040)
    local IDataVirtualSize, IDataVirtualAddress, IDataSizeOfRawData, IDataPointerToRawData = section_header('.idata', 0x00000000c0300040)

    lines[TextPointerToRawData] = rdd(_)
    lines[TextVirtualAddress] = lines[TextPointerToRawData]
    lines[SizeOfHeaders] = rdd(_)

    local _TEXT = _
    local Entrypoint = _

    -- 200 _text

    db(0xe8)
    local InitCallee, InitAddress = skipln(4), _


    -- Write
    db(0x48) db(0x89) db(0xc1) -- mov rcx, [StandardHandle]
    db(0x48) db(0xba) local MessagePointer = skipln(4) dd(0) -- movabs rdx, message
    db(0x41) db(0xb8) db(17) db(0) db(0) db(0) -- mov r8d, 17
    db(0x4c) db(0x8b) db(0x0c) db(0x25) local BytesPointer = skipln(4)
    db(0x6a) db(0)

    db(0xff)
    db(0x14)
    db(0x25)
    local WriteFileCall = skipln(4)

    -- Exit
    db(0x48) db(0x31) db(0xc9)

    db(0xff)
    db(0x14)
    db(0x25)
    local ExitProcessCall = skipln(4)
    
    -- OUTPUT

    local OUTPUT_INIT = _
    lines[InitCallee] = rdd(_ - InitAddress)

    db(0x48) -- mov rcx, -11
    db(0xc7)
    db(0xc1)
    db(0xf5)
    db(0xff)
    db(0xff)
    db(0xff)

    db(0xff) -- call GetStdHandle
    db(0x14)
    db(0x25)
    local GetStdCall = skipln(4)

    db(0x48) db(0x89) db(0x04) db(0x25) local StandardHandle1 = skipln(4) -- Write to memory

    db(0xc3) -- ret

    local OUTPUT_WRITE = _
    --lines[WriteCallee] = rdd(_ - WriteAddress)

    db(0xc3) -- ret


    lines[TextSizeOfRawData] = rdd(_ - Entrypoint)
    lines[TextVirtualSize] = lines[TextSizeOfRawData]


    lines[DataPointerToRawData] = rdd(_)
    lines[DataVirtualAddress] = lines[DataPointerToRawData]

    local _DATA = _

    -- PROG
    local MESSAGE = _
    txt('Hello PE world!') db(0x0d) db(0x0a)
    lines[MessagePointer] = rdd(MESSAGE + 0x400000)

    -- OUTPUT
    local STDHANDLE = _
    dq("0")

    local INTERNAL_VALUE = _
    dq("0")
    lines[BytesPointer] = rdd(INTERNAL_VALUE + 0x400000)

    lines[StandardHandle1] = rdd(STDHANDLE + 0x400000)
    --lines[StandardHandle2] = rdd(STDHANDLE + 0x400000)

    local Kernel32 = _
    txt('KERNEL32.DLL')
    db(0)

    lines[DataSizeOfRawData] = rdd(_ - _DATA)
    lines[DataVirtualSize] = lines[DataSizeOfRawData]

    lines[SizeOfInitializedData] = lines[DataSizeOfRawData]
    lines[SizeOfCode] = lines[TextSizeOfRawData]
    lines[BaseOfCode] = lines[TextVirtualAddress]
    lines[AddressOfEntryPoint] = lines[TextVirtualAddress]
    lines[ImportData] = rdd(_)


    lines[IDataPointerToRawData] = rdd(_)
    lines[IDataVirtualAddress] = lines[IDataPointerToRawData]

    lines[IATData] = rdd(_)

    local _IDATA = _

    local Kern32_RVA = skipln(4)
    dd(0)
    dd(0)
    dd(Kernel32)
    local Kern32_Thunk = skipln(4)

    dd(0)
    dd(0)
    dd(0)
    dd(0)
    dd(0)

    lines[ImportSize] = rdd(_ - _IDATA)
    lines[Kern32_RVA] = rdd(_)
    lines[Kern32_Thunk] = rdd(_)
    lines[IATSize] = rdd(_ - _IDATA)

    local GetStdHandleLookup, GetStdHandleAddress = skipln(8), _ - 8
    local ExitProcessLookup, ExitProcessAddress = skipln(8), _ - 8
    local WriteFileLookup, WriteFileAddress = skipln(8), _ - 8
    dq("0")

    lines[WriteFileCall] = rdd(WriteFileAddress + 0x400000)
    lines[GetStdCall] = rdd(GetStdHandleAddress + 0x400000)
    lines[ExitProcessCall] = rdd(ExitProcessAddress + 0x400000)


    local HintTable = _

    lines[GetStdHandleLookup] = rdq(_)

    dw(0)
    txt('GetStdHandle')
    db(0)
    db(0)

    lines[ExitProcessLookup] = rdq(_)

    dw(0)
    txt('ExitProcess')

    lines[WriteFileLookup] = rdq(_)

    dw(0)
    txt('WriteFile')

    
    lines[IDataSizeOfRawData] = rdd(_ - _IDATA)
    lines[IDataVirtualSize] = lines[IDataSizeOfRawData]
    lines[SizeOfImage] = rdd(_)

    while (_ % alignment) ~= 1 and (_ % alignment) ~= 0 do
        dw(0)
    end
end

return function(f, o, a)
    file = f
    options = o
    alignment = tonumber(a)

    header()

    for i, line in ipairs(lines) do
        f:write(line)
    end
end