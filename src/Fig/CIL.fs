module Fig.CIL

open System.IO
open System.Text

// Misc. notes:
//  - Info on Relative Virtual Address (RVA) can be found at 9.4
//    Also, from 4.15
//    RVA stands for Relative Virtual Address, the offset of the field from the
//    base address at which its containing PE file is loaded into memory)

type DLLReader(stream : Stream) =
    inherit BinaryReader(stream)

    let mutable posStack = []

    member x.PushPos (pos : int64) =
        posStack <- stream.Position :: posStack
        stream.Seek (pos, SeekOrigin.Begin) |> ignore

    member x.PopPos () =
        match posStack with
        | headPos :: stackTail ->
            posStack <- stackTail
            stream.Seek (headPos, SeekOrigin.Begin) |> ignore
        | [] ->
            failwith "attempted to pop an empty position stack"

let readBytesEq (br : BinaryReader) (expectBytes : byte array) (name : string) =
    let inBytes = br.ReadBytes expectBytes.Length
    if inBytes <> expectBytes then
        //failwith (sprintf "expected \"%s\" to be %A but read %A" name expectBytes inBytes)
        printfn "expected \"%s\" to be %A but read %A" name expectBytes inBytes

let readByteEq (br : BinaryReader) (expectByte : byte) (name : string) =
    let inByte = br.ReadByte ()
    if inByte <> expectByte then
        //failwith (sprintf "expected \"%s\" to be %X but read %X" name expectByte inByte)
        printfn "expected \"%s\" to be %X but read %X" name expectByte inByte

let readShortEq (br : BinaryReader) (expectShort : uint16) (name : string) =
    let inShort = br.ReadUInt16 ()
    if inShort <> expectShort then
        //failwith (sprintf "expected \"%s\" to be %X but read %X" name expectShort inShort)
        printfn "expected \"%s\" to be %X but read %X" name expectShort inShort

let readIntEq (br : BinaryReader) (expectInt : uint32) (name : string) =
    let inInt = br.ReadUInt32 ()
    if inInt <> expectInt then
        //failwith (sprintf "expected \"%s\" to be %X but read %X" name expectInt inInt)
        printfn "expected \"%s\" to be %X but read %X" name expectInt inInt

let readLongEq (br : BinaryReader) (expectLong : uint64) (name : string) =
    let inLong = br.ReadUInt64 ()
    if inLong <> expectLong then
        printfn "expected \"%s\" to be %X but read %X" name expectLong inLong

let readASCII (br : BinaryReader) =
    let sb = new StringBuilder()
    let mutable currByte = br.ReadByte ()
    while currByte <> 0uy do
        sb.Append (char currByte) |> ignore
        currByte <- br.ReadByte ()
    sb.ToString ()

let readFixedASCII (br : BinaryReader) (fixedLen : int) =
    let sb = new StringBuilder(fixedLen)
    let bytes = br.ReadBytes fixedLen
    let mutable i = 0
    while i < bytes.Length && bytes.[i] <> 0uy do
        sb.Append (char bytes.[i]) |> ignore
        i <- i + 1
    sb.ToString ()

// see EMCA-335 25.2.1
let readMSDOSHeader (br : BinaryReader) =
    let prePEOffsetBytes =
        [| 0x4d; 0x5a; 0x90; 0x00; 0x03; 0x00; 0x00; 0x00;
           0x04; 0x00; 0x00; 0x00; 0xFF; 0xFF; 0x00; 0x00;
           0xb8; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
           0x40; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
           0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
           0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
           0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00;
           0x00; 0x00; 0x00; 0x00 |]
    let prePEOffsetBytes = Array.map byte prePEOffsetBytes
    readBytesEq br prePEOffsetBytes "pre-PE offset"
    
    let peOffset = br.ReadUInt32 ()
    
    let postPEOffsetBytes =
        [| 0x0e; 0x1f; 0xba; 0x0e; 0x00; 0xb4; 0x09; 0xcd;
           0x21; 0xb8; 0x01; 0x4c; 0xcd; 0x21; 0x54; 0x68;
           0x69; 0x73; 0x20; 0x70; 0x72; 0x6f; 0x67; 0x72;
           0x61; 0x6d; 0x20; 0x63; 0x61; 0x6e; 0x6e; 0x6f;
           0x74; 0x20; 0x62; 0x65; 0x20; 0x72; 0x75; 0x6e;
           0x20; 0x69; 0x6e; 0x20; 0x44; 0x4f; 0x53; 0x20;
           0x6d; 0x6f; 0x64; 0x65; 0x2e; 0x0d; 0x0d; 0x0a;
           0x24; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00; 0x00 |]
    let postPEOffsetBytes = Array.map byte postPEOffsetBytes
    readBytesEq br postPEOffsetBytes "post-PE offset"

    peOffset

// specified in EMCA-335 25.2.2
type SubSystem = WindowsCUI | WindowsGUI

type PEOptionalHeader = {
    // 25.2.3.1 standard fields
    codeSize : uint32
    initDataSize : uint32
    uninitDataSize : uint32
    entryPointRVA : uint32
    baseOfCode : uint32
    baseOfData : uint32

    // 25.2.3.2 NT specific fields
    imageBase : uint32
    sectionAlignment : uint32
    fileAlignment : uint32
    imageSize : uint32
    headerSize : uint32
    subSystem : SubSystem
    dllFlags : uint16

    // 25.2.3.3 PE header data directories
    importTableRVA : uint32
    importTableSize : uint32
    baseRelocationRVA : uint32
    baseRelocationSize : uint32
    importAddressTableRVA : uint32
    importAddressTableSize : uint32
    cliHeaderRVA : uint32
    cliHeaderSize : uint32}

type PEHeader = {
    numSections : uint16
    timeStampSecs : uint32
    is32BitMachine : bool
    isDLL : bool
    optHeader : PEOptionalHeader option}

// specified in EMCA-335 25.3.1
let readImportTables (br : BinaryReader) =
    let importLookupTableRVA = br.ReadUInt32 ()
    printfn "importLookupTableRVA = %X" importLookupTableRVA
    readIntEq br 0u "DateTimeStamp"
    readIntEq br 0u "ForwarderChain"
    let nameRVA = br.ReadUInt32 ()
    printfn "nameRVA = %X" nameRVA
    let importAddressTableRVA = br.ReadUInt32 ()
    printfn "importAddressTableRVA = %X" importAddressTableRVA
    readBytesEq br (Array.create 20 0x00uy) "import table RVA padding"

let readPEHeader (br : BinaryReader) =
    let peOffset = readMSDOSHeader br
    br.BaseStream.Seek (int64 peOffset, SeekOrigin.Begin) |> ignore
    
    readBytesEq br [|byte 'P'; byte 'E'; 0uy; 0uy|] "PE header start"
    readShortEq br 0x014Cus "machine"

    let numSections = br.ReadUInt16 ()
    let timeStampSecs = br.ReadUInt32 ()

    readIntEq br 0u "pointer to symbol table"
    readIntEq br 0u "number of symbols"

    let optHeaderSize = br.ReadUInt16 ()
    if not (optHeaderSize = 0us || optHeaderSize = 224us) then
        failwith "expected optional header size to be 0 or 224"

    let currByte = br.ReadByte ()
    if 0x01uy &&& currByte <> 0x00uy then
        failwith "IMAGE_FILE_RELOCS_STRIPPED expected to be unset"
    if 0x02uy &&& currByte = 0x00uy then
        failwith "IMAGE_FILE_EXECUTABLE_IMAGE expected to be set"

    let currByte = br.ReadByte ()
    // Shall be one if and only if
    // COMIMAGE_FLAGS_32BITREQUIRED is
    // one (25.3.3.1)
    let is32BitMachine = currByte &&& 0x01uy <> 0x00uy
    let isDLL = currByte &&& 0x20uy <> 0x00uy

    // 25.2.3 the PE optional header
    // TODO actually do something with the optional header
    let optHeader =
        if optHeaderSize = 0us then
            None
        else
            // 25.2.3.1 standard fields
            readShortEq br 0x010Bus "magic"
            readByteEq br 0x06uy "LMajor"
            readByteEq br 0x00uy "LMinor"
            let codeSize = br.ReadUInt32 ()
            let initDataSize = br.ReadUInt32 ()
            let uninitDataSize = br.ReadUInt32 ()
            let entryPointRVA = br.ReadUInt32 ()
            let baseOfCode = br.ReadUInt32 ()
            let baseOfData = br.ReadUInt32 ()

            // 25.2.3.2 NT specific fields
            let imageBase = br.ReadUInt32 ()
            if imageBase &&& 0x0000FFFFu <> 0u then
                failwith "image base should be a multiple of 0x10000"
            let sectionAlignment = br.ReadUInt32 ()
            let fileAlignment = br.ReadUInt32 ()
            if fileAlignment <> 0x00000200u then
                failwith "file alignment expected to be 0x200"
            readShortEq br 5us "OS Major"
            readShortEq br 0us "OS Minor"
            readShortEq br 0us "User Major"
            readShortEq br 0us "User Minor"
            readShortEq br 5us "SubSys Major"
            readShortEq br 0us "SubSys Minor"
            readIntEq br 0u "reserved"
            let imageSize = br.ReadUInt32 ()
            if imageSize % sectionAlignment <> 0u then
                printfn "image size expected to be a multiple of section alignment"
            let headerSize = br.ReadUInt32 ()
            if headerSize % fileAlignment <> 0u then
                printfn "header size expected to be a multiple of file alignment"
            readIntEq br 0u "file checksum"
            let subSystem =
                match br.ReadUInt16 () with
                | 0x0003us -> WindowsCUI
                | 0x0002us -> WindowsGUI
                | i -> failwith (sprintf "unexpected sub-system %X" i)
            let dllFlags = br.ReadUInt16 ()
            if dllFlags &&& 0x100Fus <> 0us then
                failwith "expected DLL flags to be 0 for mask 0x100F"
            readIntEq br 0x00100000u "stack reserve size"
            readIntEq br 0x00001000u "stack commit size"
            readIntEq br 0x00100000u "heap reserve size"
            readIntEq br 0x00001000u "heap commit size"
            readIntEq br 0x00000000u "loader flags"
            readIntEq br 0x00000010u "number of data directories"

            // 25.2.3.3 PE header data directories
            readLongEq br 0uL "export table"
            let importTableRVA = br.ReadUInt32 ()
            let importTableSize = br.ReadUInt32 ()
            //br.PushPos (int64 importTableRVA)
            //printfn "importtbl rva %i %X and size %i %X" importTableRVA importTableRVA importTableSize importTableSize
            //readImportTables br |> ignore
            //printfn "READ"
            //br.PopPos ()
            //printfn "POPPED"
            readLongEq br 0uL "resource table"
            readLongEq br 0uL "exception table"
            readLongEq br 0uL "certificate table"
            let baseRelocationRVA = br.ReadUInt32 ()
            let baseRelocationSize = br.ReadUInt32 ()
            readLongEq br 0uL "debug"
            readLongEq br 0uL "copyright"
            readLongEq br 0uL "global ptr"
            readLongEq br 0uL "tls table"
            readLongEq br 0uL "load config table"
            readLongEq br 0uL "bound import table"
            let importAddressTableRVA = br.ReadUInt32 ()
            let importAddressTableSize = br.ReadUInt32 ()
            readLongEq br 0uL "delay import descriptor"
            let cliHeaderRVA = br.ReadUInt32 ()
            let cliHeaderSize = br.ReadUInt32 ()
            readLongEq br 0uL "reserved"
            Some {
                // 25.2.3.1 standard fields
                PEOptionalHeader.codeSize = codeSize
                PEOptionalHeader.initDataSize = initDataSize
                PEOptionalHeader.uninitDataSize = uninitDataSize
                PEOptionalHeader.entryPointRVA = entryPointRVA
                PEOptionalHeader.baseOfCode = baseOfCode
                PEOptionalHeader.baseOfData = baseOfData

                // 25.2.3.2 NT specific fields
                PEOptionalHeader.imageBase = imageBase
                PEOptionalHeader.sectionAlignment = sectionAlignment
                PEOptionalHeader.fileAlignment = fileAlignment
                PEOptionalHeader.imageSize = imageSize
                PEOptionalHeader.headerSize = headerSize
                PEOptionalHeader.subSystem = subSystem
                PEOptionalHeader.dllFlags = dllFlags

                // 25.2.3.3 PE header data directories
                PEOptionalHeader.importTableRVA = importTableRVA
                PEOptionalHeader.importTableSize = importTableSize
                PEOptionalHeader.baseRelocationRVA = baseRelocationRVA
                PEOptionalHeader.baseRelocationSize = baseRelocationSize
                PEOptionalHeader.importAddressTableRVA = importAddressTableRVA
                PEOptionalHeader.importAddressTableSize = importAddressTableSize
                PEOptionalHeader.cliHeaderRVA = cliHeaderRVA
                PEOptionalHeader.cliHeaderSize = cliHeaderSize}

    // return the PE header
    {
        PEHeader.numSections = numSections
        PEHeader.timeStampSecs = timeStampSecs
        PEHeader.is32BitMachine = is32BitMachine
        PEHeader.isDLL = isDLL
        PEHeader.optHeader = optHeader
    }

// specified in EMCA-335 25.3
type SectionHeader = {
    name : string
    virtSize : uint32
    virtAddr : uint32
    sizeOfRawData : uint32
    ptrToRawData : uint32
    containsCode : bool
    containsInitData : bool
    containsUninitData : bool
    memExec : bool
    memRead : bool
    memWrite : bool}

let readSectionHeader (br : BinaryReader) =
    let name = readFixedASCII br 8
    let virtualSize = br.ReadUInt32 ()
    let virtualAddr = br.ReadUInt32 ()
    let sizeOfRawData = br.ReadUInt32 ()
    let ptrToRawData = br.ReadUInt32 ()
    readIntEq br 0u "PointerToRelocations"
    readIntEq br 0u "PointerToLinenumbers"
    readShortEq br 0us "NumberOfRelocations"
    readShortEq br 0us "NumberOfLinenumbers"
    let currByte = br.ReadByte ()
    let containsCode = currByte &&& 0x20uy <> 0x00uy
    let containsInitData = currByte &&& 0x40uy <> 0x00uy
    let containsUninitData = currByte &&& 0x80uy <> 0x00uy
    br.BaseStream.Seek (2L, SeekOrigin.Current) |> ignore
    let currByte = br.ReadByte ()
    let memExec = currByte &&& 0x20uy <> 0x00uy
    let memRead = currByte &&& 0x40uy <> 0x00uy
    let memWrite = currByte &&& 0x80uy <> 0x00uy
    
    {
        SectionHeader.name = name
        SectionHeader.virtSize = virtualSize
        SectionHeader.virtAddr = virtualAddr
        SectionHeader.sizeOfRawData = sizeOfRawData
        SectionHeader.ptrToRawData = ptrToRawData
        SectionHeader.containsCode = containsCode
        SectionHeader.containsInitData = containsInitData
        SectionHeader.containsUninitData = containsUninitData
        SectionHeader.memExec = memExec
        SectionHeader.memRead = memRead
        SectionHeader.memWrite = memWrite
    }

let readSectionHeaders (br : BinaryReader) (pe : PEHeader) =
    [|for _ in 1us .. pe.numSections -> readSectionHeader br|]

