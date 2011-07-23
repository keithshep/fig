module Fig.CIL

open System.IO
open System.Text

let warnf fmt = eprintfn fmt

// Misc. notes:
//  - Info on Relative Virtual Address (RVA) can be found at 9.4
//    Also, from 4.15
//    RVA stands for Relative Virtual Address, the offset of the field from the
//    base address at which its containing PE file is loaded into memory)

type DLLReader(stream : Stream) =
    inherit BinaryReader(stream)

    let mutable posStack = []

    member x.PushPos () = posStack <- stream.Position :: posStack

    member x.PushPos (pos : int64) =
        x.PushPos ()
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

let readString (br : BinaryReader) (enc : Encoding) =
    enc.GetString [|
        let currByte = ref (br.ReadByte ())
        while !currByte <> 0uy do
            yield !currByte
            currByte := br.ReadByte ()|]

let readASCII (br : BinaryReader) = readString br Encoding.ASCII

let readUTF8 (br : BinaryReader) = readString br Encoding.UTF8

let readFixedASCII (br : BinaryReader) (fixedLen : int) =
    let sb = new StringBuilder(fixedLen)
    let bytes = br.ReadBytes fixedLen
    let mutable i = 0
    while i < bytes.Length && bytes.[i] <> 0uy do
        sb.Append (char bytes.[i]) |> ignore
        i <- i + 1
    sb.ToString ()

let readAlignedASCII (br : BinaryReader) (align : int) =
    let sb = new StringBuilder()
    let mutable currByte = br.ReadByte ()
    let mutable bytesRead = 1
    while currByte <> 0uy do
        sb.Append (char currByte) |> ignore
        currByte <- br.ReadByte ()
        bytesRead <- bytesRead + 1
    let overhang = bytesRead % align
    if overhang <> 0 then
        let padding = align - overhang
        br.BaseStream.Seek (int64 padding, SeekOrigin.Current) |> ignore
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

type CLIHeader = {
    majorRuntimeVersion : uint16
    minorRuntimeVersion : uint16
    metaDataRVA : uint32
    metaDataSize : uint32
    flags : uint32
    entryPointTok : uint32
    resourcesRVA : uint32
    resourcesSize : uint32
    strongNameSig : uint64
    vTableFixupsRVA : uint32
    vTableFixupsSize : uint32}

// From EMCA-335 25
// The PE format frequently uses the term RVA (Relative Virtual Address). An RVA is the address of an item
// once loaded into memory, with the base address of the image file subtracted from it (i.e., the offset from the
// base address where the file is loaded). The RVA of an item will almost always differ from its position within
// the file on disk. To compute the file position of an item with RVA r, search all the sections in the PE file to find
// the section with RVA s, length l and file position p in which the RVA lies, ie s <= r < s+l. The file position of
// the item is then given by p+(r-s).
let rec rvaToDiskPosOpt (secHeaders : SectionHeader list) (r : uint32) =
    match secHeaders with
    | {virtSize = l; virtAddr = s; ptrToRawData = p} :: hdrTail ->
        if s <= r && r < s + l then
            let diskPos = p + (r - s)
            Some (int64 diskPos)
        else
            rvaToDiskPosOpt hdrTail r
    | [] ->
        None

let rvaToDiskPos (secHeaders : SectionHeader list) (r : uint32) =
    match rvaToDiskPosOpt secHeaders r with
    | Some x -> x
    | None -> failwith (sprintf "failed to locate RVA %X" r)

// specified in EMCA-335 25.2.2
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
            //printfn "CLI header: %i %i" cliHeaderRVA cliHeaderSize
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
    [for _ in 1us .. pe.numSections -> readSectionHeader br]

// 25.3.3 CLI Header
let readCLIHeader (br : BinaryReader) (secHdrs : SectionHeader list) (peHdr : PEHeader) =
    match peHdr.optHeader with
    | None -> failwith "can't read CLI with missing optional PE header"
    | Some {cliHeaderRVA = rvi} ->
        br.BaseStream.Seek (rvaToDiskPos secHdrs rvi, SeekOrigin.Begin) |> ignore
        readIntEq br 72u "size in bytes"
        let majorRuntimeVersion = br.ReadUInt16 ()
        let minorRuntimeVersion = br.ReadUInt16 ()
        let metaDataRVA = br.ReadUInt32 ()
        let metaDataSize = br.ReadUInt32 ()
        let flags = br.ReadUInt32 ()
        let entryPointTok = br.ReadUInt32 ()
        printfn "entry point tok: %i" entryPointTok
        let resourcesRVA = br.ReadUInt32 ()
        let resourcesSize = br.ReadUInt32 ()
        let strongNameSig = br.ReadUInt64 ()
        readLongEq br 0uL "code manager table"
        let vTableFixupsRVA = br.ReadUInt32 ()
        let vTableFixupsSize = br.ReadUInt32 ()
        readLongEq br 0uL "export address table jumps"
        readLongEq br 0uL "managed native header"
        
        {
            CLIHeader.majorRuntimeVersion = majorRuntimeVersion
            CLIHeader.minorRuntimeVersion = minorRuntimeVersion
            CLIHeader.metaDataRVA = metaDataRVA
            CLIHeader.metaDataSize = metaDataSize
            CLIHeader.flags = flags
            CLIHeader.entryPointTok = entryPointTok
            CLIHeader.resourcesRVA = resourcesRVA
            CLIHeader.resourcesSize = resourcesSize
            CLIHeader.strongNameSig = strongNameSig
            CLIHeader.vTableFixupsRVA = vTableFixupsRVA
            CLIHeader.vTableFixupsSize = vTableFixupsSize
        }

let readStreamHeader (br : BinaryReader) =
    let offset = br.ReadUInt32 ()
    let size = br.ReadUInt32 ()
    let name = readAlignedASCII br 4
    (offset, size, name)

let readStreamHeaders (br : BinaryReader) (secHdrs : SectionHeader list) (cliHeader : CLIHeader) =
    br.BaseStream.Seek (rvaToDiskPos secHdrs cliHeader.metaDataRVA, SeekOrigin.Begin) |> ignore
    readIntEq br 0x424A5342u "magic signature for physical metadata"
    br.BaseStream.Seek (4L, SeekOrigin.Current) |> ignore
    readIntEq br 0u "reserved"
    let versionStrLen = br.ReadUInt32 ()
    let tempPos = br.BaseStream.Position
    printfn "version string: '%s', alloc: %i" (readASCII br) versionStrLen
    br.BaseStream.Seek (tempPos + int64 versionStrLen, SeekOrigin.Begin) |> ignore
    readShortEq br 0us "meta data flags"
    let numStreams = br.ReadUInt16 ()
    printfn "num streams %i" numStreams
    
    Map.ofList
        [for _ in 1us .. numStreams do
            let offset, size, name = readStreamHeader br
            printfn "offset = %i, size = %i, name = '%s'" offset size name
            yield (name, (offset, size))]

type MetadataTableKind =
    | Assembly = 0x20
    | AssemblyOS = 0x22
    | AssemblyProcessor = 0x21
    | AssemblyRef = 0x23
    | AssemblyRefOS = 0x25
    | AssemblyRefProcessor = 0x24
    | ClassLayout = 0x0F
    | Constant = 0x0B
    | CustomAttribute = 0x0C
    | DeclSecurity = 0x0E
    | EventMap = 0x12
    | Event = 0x14
    | ExportedType = 0x27
    | Field = 0x04
    | FieldLayout = 0x10
    | FieldMarshal = 0x0D
    | FieldRVA = 0x1D
    | File = 0x26
    | GenericParam = 0x2A
    | GenericParamConstraint = 0x2C
    | ImplMap = 0x1C
    | InterfaceImpl = 0x09
    | ManifestResource = 0x28
    | MemberRef = 0x0A
    | MethodDef = 0x06
    | MethodImpl = 0x19
    | MethodSemantics = 0x18
    | MethodSpec = 0x2B
    | Module = 0x00
    | ModuleRef = 0x1A
    | NestedClass = 0x29
    | Param = 0x08
    | Property = 0x17
    | PropertyMap = 0x15
    | StandAloneSig = 0x11
    | TypeDef = 0x02
    | TypeRef = 0x01
    | TypeSpec = 0x1B

let sortedTableEnums =
    [|for x in System.Enum.GetValues typeof<MetadataTableKind> ->
        enum<MetadataTableKind> (x :?> int)|]

let isMetadataTableValid (validTblBits : uint64) (mt : MetadataTableKind) =
    (1uL <<< int mt) &&& validTblBits <> 0uL

let assertTableBitsValid (validTblBits : uint64) =
    let mutable maskedBits = validTblBits
    for mt in sortedTableEnums do
        let mask = ~~~(1uL <<< int mt)
        maskedBits <- maskedBits &&& mask

    if maskedBits <> 0uL then failwith (sprintf "bad bits: %X" maskedBits)

type CodedIndexKind =
    | TypeDefOrRef
    | HasConstant
    | HasCustomAttribute
    | HasFieldMarshall
    | HasDeclSecurity
    | MemberRefParent
    | HasSemantics
    | MethodDefOrRef
    | MemberForwarded
    | Implementation
    | CustomAttributeType
    | ResolutionScope
    | TypeOrMethodDef

let codeBitCount = function
    | TypeDefOrRef -> 2
    | HasConstant -> 2
    | HasCustomAttribute -> 5
    | HasFieldMarshall -> 1
    | HasDeclSecurity -> 2
    | MemberRefParent -> 3
    | HasSemantics -> 1
    | MethodDefOrRef -> 1
    | MemberForwarded -> 1
    | Implementation -> 2
    | CustomAttributeType -> 3
    | ResolutionScope -> 2
    | TypeOrMethodDef -> 1

let possibleTableKinds = function
    | TypeDefOrRef -> [|MetadataTableKind.TypeDef; MetadataTableKind.TypeRef; MetadataTableKind.TypeSpec|]
    | HasConstant -> [|MetadataTableKind.Field; MetadataTableKind.Param; MetadataTableKind.Property|]
    | HasCustomAttribute ->
        [|MetadataTableKind.MethodDef; MetadataTableKind.Field; MetadataTableKind.TypeRef;
          MetadataTableKind.TypeDef; MetadataTableKind.Param; MetadataTableKind.InterfaceImpl;
          MetadataTableKind.MemberRef; MetadataTableKind.Module;
          (* TODO documented as Permission not sure if this is valid *) MetadataTableKind.DeclSecurity;
          MetadataTableKind.Property; MetadataTableKind.Event; MetadataTableKind.StandAloneSig;
          MetadataTableKind.ModuleRef; MetadataTableKind.TypeSpec; MetadataTableKind.Assembly;
          MetadataTableKind.AssemblyRef; MetadataTableKind.File; MetadataTableKind.ExportedType;
          MetadataTableKind.ManifestResource; MetadataTableKind.GenericParam;
          MetadataTableKind.GenericParamConstraint; MetadataTableKind.MethodSpec|]
    | HasFieldMarshall -> [|MetadataTableKind.Field; MetadataTableKind.Param|]
    | HasDeclSecurity -> [|MetadataTableKind.TypeDef; MetadataTableKind.MethodDef; MetadataTableKind.Assembly|]
    | MemberRefParent ->
        [|MetadataTableKind.TypeDef; MetadataTableKind.TypeRef; MetadataTableKind.ModuleRef;
          MetadataTableKind.MethodDef; MetadataTableKind.TypeSpec|]
    | HasSemantics -> [|MetadataTableKind.Event; MetadataTableKind.Property|]
    | MethodDefOrRef -> [|MetadataTableKind.MethodDef; MetadataTableKind.MemberRef|]
    | MemberForwarded -> [|MetadataTableKind.Field; MetadataTableKind.MethodDef|]
    | Implementation -> [|MetadataTableKind.File; MetadataTableKind.AssemblyRef; MetadataTableKind.ExportedType|]
    | CustomAttributeType -> [|MetadataTableKind.MethodDef; MetadataTableKind.MemberRef|]
    | ResolutionScope ->
        [|MetadataTableKind.Module; MetadataTableKind.ModuleRef;
          MetadataTableKind.AssemblyRef; MetadataTableKind.TypeRef|]
    | TypeOrMethodDef -> [|MetadataTableKind.TypeDef; MetadataTableKind.MethodDef|]

let resolveTableKind (cik : CodedIndexKind) (i : int) =
    match cik with
    | CustomAttributeType ->
        // CustomAttributeType is a special case since it isn't directly indexable
        match i with
        | 2 -> MetadataTableKind.MethodDef
        | 3 -> MetadataTableKind.MemberRef
        | _ -> failwith (sprintf "bad index used for CustomAttributeType: %i" i)

    | _ -> (possibleTableKinds cik).[i]

type AssemblyRow = {
    hashAlgId : uint32
    majorVersion : uint16
    minorVersion : uint16
    buildNumber : uint16
    revisionNumber : uint16
    flags : uint32
    pubKeyBlobIdx : uint32
    name : string
    culture : string}

type AssemblyRefRow = {
    majorVersion : uint16
    minorVersion : uint16
    buildNumber : uint16
    revisionNumber : uint16
    flags : uint32
    publicKeyOrTokenIndex : uint32
    name : string
    culture : string
    hashValueIndex : uint32}

type ClassLayoutRow = {
    packingSize : uint16
    classSize : uint32
    parentIndex : uint32}

type ConstantRow = {
    typeVal : byte
    parentKind : MetadataTableKind
    parentIndex : uint32
    valueIndex : uint32}

type CustomAttributeRow = {
    parentKind : MetadataTableKind
    parentIndex : uint32
    // The column called Type is slightly misleading
    // it actually indexes a constructor method
    // the owner of that constructor method is
    //the Type of the Custom Attribute.
    typeKind : MetadataTableKind
    typeIndex : uint32
    valueIndex : uint32}

type DeclSecurityRow = {
    action : uint16
    parentKind : MetadataTableKind
    parentIndex : uint32
    permissionSetIndex : uint32}

type FieldRow = {
    fieldAttrFlags : uint16
    name : string
    signatureIndex : uint32}

type FieldMarshalRow = {
    parentKind : MetadataTableKind
    parentIndex : uint32
    nativeTypeIndex : uint32}

type FieldRVARow = {
    rva : uint32
    fieldIndex : uint32}

type GenericParamRow = {
    number : uint16
    flags : uint16
    ownerKind : MetadataTableKind
    ownerIndex : uint32
    name : string}

type GenericParamConstraintRow = {
    ownerIndex : uint32
    constraintKind : MetadataTableKind
    constraintIndex : uint32}

type ImplMapRow = {
    mappingFlags : uint16
    //it only ever indexes the MethodDef table, since Field export is not supported
    memberForwardedKind : MetadataTableKind
    memberForwardedIndex : uint32
    importName : string
    importScopeIndex : uint32}

type InterfaceImplRow = {
    classIndex : uint32
    ifaceKind : MetadataTableKind
    ifaceIndex : uint32}

type ManifestResourceRow = {
    offset : uint32
    flags : uint32
    name : string
    implKind : MetadataTableKind
    implIndex : uint32}

type MemberRefRow = {
    classKind : MetadataTableKind
    classIndex : uint32
    name : string
    signatureIndex : uint32}

type MethodDefRow = {
    rva : uint32
    implFlags : uint16
    flags : uint16
    name : string
    signatureIndex : uint32
    paramIndex : uint32}

type MethodImplRow = {
    classIndex : uint32
    methodBodyKind : MetadataTableKind
    methodBodyIndex : uint32
    methodDecKind : MetadataTableKind
    methodDecIndex : uint32}

type MethodSemanticsRow = {
    semanticsFlags : uint16
    methodIndex : uint32
    assocKind : MetadataTableKind
    assocIndex : uint32}

type MethodSpecRow = {
    methodKind : MetadataTableKind
    methodIndex : uint32
    instIndex : uint32}

type ModuleRow = {
    name : string
    mvidIndex : uint32
    encIDIndex : uint32
    encBaseIdIndex : uint32}

type ModuleRefRow = {
    name : string}

type NestedClassRow = {
    nestedClassIndex : uint32
    enclosingClassIndex : uint32}

type ParamRow = {
    flags : uint16
    sequence : uint16
    name : string}

type PropertyRow = {
    flags : uint16
    name : string
    // The name of this column is misleading.  It does not index
    // a TypeDef or TypeRef table. Instead it indexes the
    // signature in the Blob heap of the Property
    typeIndex : uint32}

type PropertyMapRow = {
    parentIndex : uint32
    propertyListIndex : uint32}

type StandAloneSigRow = {
    signatureIndex : uint32}

type TypeDefRow = {
    flags : uint32
    typeName : string
    typeNamespace : string
    extendsKind : MetadataTableKind
    extendsIndex : uint32
    fieldsIndex : uint32
    methodsIndex : uint32}

type TypeRefRow = {
    resolutionScopeKind : MetadataTableKind
    resolutionScopeIndex : uint32
    typeName : string
    typeNamespace : string}

type TypeSpecRow = {
    sigIndex : uint32}

type MetadataTables = {
    assemblies : AssemblyRow array
    assemblyRefs : AssemblyRefRow array
    classLayouts : ClassLayoutRow array
    constants : ConstantRow array
    customAttributes : CustomAttributeRow array
    declSecurities : DeclSecurityRow array
    fields : FieldRow array
    fieldMarshals : FieldMarshalRow array
    fieldRVAs : FieldRVARow array
    genericParams : GenericParamRow array
    genericParamConstraints : GenericParamConstraintRow array
    implMaps : ImplMapRow array
    interfaceImpls : InterfaceImplRow array
    manifestResources : ManifestResourceRow array
    memberRefs : MemberRefRow array
    methodDefs : MethodDefRow array
    methodImpls : MethodImplRow array
    methodSemantics : MethodSemanticsRow array
    methodSpecs : MethodSpecRow array
    modules : ModuleRow array
    moduleRefs : ModuleRefRow array
    nestedClasses : NestedClassRow array
    paramRows : ParamRow array
    properties : PropertyRow array
    propertyMaps : PropertyMapRow array
    standAloneSigs : StandAloneSigRow array
    typeDefs : TypeDefRow array
    typeRefs : TypeRefRow array
    typeSpecs : TypeSpecRow array}

let readMetadataTables
        (br : DLLReader)
        (secHdrs : SectionHeader list)
        (cliHeader : CLIHeader)
        (streamHeaders : Map<string, uint32 * uint32>) =

    // see 24.2.6
    match streamHeaders.TryFind "#~" with
    | None -> failwith "failed to find the \"#~\" stream"
    | Some (tildeOffset, tildeSize) ->
        let rraToDiskPos rootRelAddr =
            rvaToDiskPos secHdrs (cliHeader.metaDataRVA + rootRelAddr)
        br.BaseStream.Seek (rraToDiskPos tildeOffset, SeekOrigin.Begin) |> ignore
        
        readIntEq br 0u "meta tables header reserved field"
        readByteEq br 2uy "major version of table schemata"
        readByteEq br 0uy "minor version of table schemata"
        let heapSizes = br.ReadByte ()
        readByteEq br 1uy "meta tables header second reserved field"
        let validTables = br.ReadUInt64 ()
        assertTableBitsValid validTables
        let sortedTables = br.ReadUInt64 ()

        let readMaybeWideIndex isWide =
            if isWide then
                br.ReadUInt32 ()
            else
                br.ReadUInt16 () |> uint32

        let stringHeapIndicesWide = heapSizes &&& 0x01uy <> 0x00uy
        let readStringHeapIndex () = readMaybeWideIndex stringHeapIndicesWide
        let readHeapString () =
            let i = readStringHeapIndex ()
            let strOffset =
                match streamHeaders.TryFind "#Strings" with
                | Some (offset, _) -> offset
                | None -> failwith "failed to find string section"
            let strAddr = rraToDiskPos strOffset + int64 i
            br.PushPos strAddr
            let str = readUTF8 br
            br.PopPos ()
            str

        let guidHeapIndicesWide = heapSizes &&& 0x02uy <> 0x00uy
        let readGUIDHeapIndex () = readMaybeWideIndex guidHeapIndicesWide

        let blobHeapIndicesWide = heapSizes &&& 0x04uy <> 0x00uy
        let readBlobHeapIndex () = readMaybeWideIndex blobHeapIndicesWide

        let rowCounts =
            Map.ofList
                [for mt in sortedTableEnums do
                    if isMetadataTableValid validTables mt then
                        yield mt, br.ReadUInt32 ()]

        let tableIndicesWide mt =
            match rowCounts.TryFind mt with
            | None -> false
            | Some count -> count &&& 0xFFFF0000u <> 0u

        let readTableIndex mt =
            if tableIndicesWide mt then
                br.ReadUInt32 ()
            else
                br.ReadUInt16 () |> uint32

        let tableIndexWidth mt = if tableIndicesWide mt then 4L else 2L

        let codedIndicesWide (cik : CodedIndexKind) =
            let maxCount =
                Array.max
                    [|for mt in possibleTableKinds cik do
                        match rowCounts.TryFind mt with
                        | None -> ()
                        | Some x -> yield x|]
            let mask = 0xFFFF0000u ||| (0xFFFF0000u >>> codeBitCount cik)
            maxCount &&& mask <> 0u

        let readCodedIndex (cik : CodedIndexKind) =
            let rawIndex =
                if codedIndicesWide cik then
                    br.ReadUInt32 ()
                else
                    br.ReadUInt16 () |> uint32
            let cbc = codeBitCount cik
            let tableKindIndex = int (rawIndex &&& ~~~(0xFFFFFFFFu <<< cbc))
            let tableKind = resolveTableKind cik tableKindIndex
            let rowIndex = rawIndex >>> cbc
            
            tableKind, rowIndex

        let mutable assemblies = ([||] : AssemblyRow array)
        let mutable assemblyRefs = ([||] : AssemblyRefRow array)
        let mutable classLayouts = ([||] : ClassLayoutRow array)
        let mutable constants = ([||] : ConstantRow array)
        let mutable customAttributes = ([||] : CustomAttributeRow array)
        let mutable declSecurities = ([||] : DeclSecurityRow array)
        let mutable fields = ([||] : FieldRow array)
        let mutable fieldMarshals = ([||] : FieldMarshalRow array)
        let mutable fieldRVAs = ([||] : FieldRVARow array)
        let mutable genericParams = ([||] : GenericParamRow array)
        let mutable genericParamConstraints = ([||] : GenericParamConstraintRow array)
        let mutable implMaps = ([||] : ImplMapRow array)
        let mutable interfaceImpls = ([||] : InterfaceImplRow array)
        let mutable manifestResources = ([||] : ManifestResourceRow array)
        let mutable memberRefs = ([||] : MemberRefRow array)
        let mutable methodDefs = ([||] : MethodDefRow array)
        let mutable methodImpls = ([||] : MethodImplRow array)
        let mutable methodSemantics = ([||] : MethodSemanticsRow array)
        let mutable methodSpecs = ([||] : MethodSpecRow array)
        let mutable modules = ([||] : ModuleRow array)
        let mutable moduleRefs = ([||] : ModuleRefRow array)
        let mutable nestedClasses = ([||] : NestedClassRow array)
        let mutable paramRows = ([||] : ParamRow array)
        let mutable properties = ([||] : PropertyRow array)
        let mutable propertyMaps = ([||] : PropertyMapRow array)
        let mutable standAloneSigs = ([||] : StandAloneSigRow array)
        let mutable typeDefs = ([||] : TypeDefRow array)
        let mutable typeRefs = ([||] : TypeRefRow array)
        let mutable typeSpecs = ([||] : TypeSpecRow array)

        for kv in rowCounts do
            let rowCount = kv.Value
            let noImpl () = failwith (sprintf "no implementation for %A" kv.Key)
            match kv.Key with
            | MetadataTableKind.Assembly ->
                assemblies <-
                    [|for _ in 1u .. rowCount do
                        let hashAlgId = br.ReadUInt32 ()
                        let majorVersion = br.ReadUInt16 ()
                        let minorVersion = br.ReadUInt16 ()
                        let buildNumber = br.ReadUInt16 ()
                        let revisionNumber = br.ReadUInt16 ()
                        let flags = br.ReadUInt32 ()
                        let pubKeyBlobIdx = readBlobHeapIndex ()
                        let name = readHeapString ()
                        let culture = readHeapString ()
                        
                        printfn "Assembly: name=\"%s\", culture=\"%s\"" name culture

                        yield {
                            AssemblyRow.hashAlgId = hashAlgId
                            majorVersion = majorVersion
                            minorVersion = minorVersion
                            buildNumber = buildNumber
                            revisionNumber = revisionNumber
                            flags = flags
                            pubKeyBlobIdx = pubKeyBlobIdx
                            name = name
                            culture = culture}|]
            | MetadataTableKind.AssemblyOS ->
                printfn "AssemblyOS: skipping %i rows..." rowCount
                let tableSize = 4L * 3L
                br.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyProcessor ->
                printfn "AssemblyProcessor: skipping %i rows..." rowCount
                let tableSize = 4L
                br.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyRef ->
                assemblyRefs <-
                    [|for _ in 1u .. rowCount do
                        let majorVersion = br.ReadUInt16 ()
                        let minorVersion = br.ReadUInt16 ()
                        let buildNumber = br.ReadUInt16 ()
                        let revisionNumber = br.ReadUInt16 ()
                        let flags = br.ReadUInt32 ()
                        let publicKeyOrTokenIndex = readBlobHeapIndex ()
                        let name = readHeapString ()
                        let culture = readHeapString ()
                        let hashValueIndex = readBlobHeapIndex ()
                        
                        printfn "AssemblyRef: name=\"%s\", culture=\"%s\"" name culture

                        yield {
                            AssemblyRefRow.majorVersion = majorVersion
                            minorVersion = minorVersion
                            buildNumber = buildNumber
                            revisionNumber = revisionNumber
                            flags = flags
                            publicKeyOrTokenIndex = publicKeyOrTokenIndex
                            name = name
                            culture = culture
                            hashValueIndex = hashValueIndex}|]
            | MetadataTableKind.AssemblyRefOS ->
                printfn "AssemblyRefOS: skipping %i rows..." rowCount
                let tableSize = 4L * 3L + tableIndexWidth MetadataTableKind.AssemblyRef
                br.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyRefProcessor ->
                printfn "AssemblyRefProcessor: skipping %i rows..." rowCount
                let tableSize = 4L + tableIndexWidth MetadataTableKind.AssemblyRef
                br.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.ClassLayout ->
                classLayouts <-
                    [|for _ in 1u .. rowCount do
                        let packingSize = br.ReadUInt16 ()
                        let classSize = br.ReadUInt32 ()
                        let parentIndex = readTableIndex MetadataTableKind.TypeDef

                        printfn "ClassLayout: packingSize=%i, classSize=%i, parent=%i" packingSize classSize parentIndex

                        yield {
                            ClassLayoutRow.packingSize = packingSize
                            classSize = classSize
                            parentIndex = parentIndex}|]
            | MetadataTableKind.Constant ->
                constants <-
                    [|for _ in 1u .. rowCount do
                        let typeVal = br.ReadByte ()
                        readByteEq br 0x00uy "constant type padding"
                        let parentKind, parentIndex = readCodedIndex HasConstant
                        let valueIndex = readBlobHeapIndex ()

                        printfn "Constant: type=0x%X, parent=(%A, %i), value=%i" typeVal parentKind parentIndex valueIndex

                        yield {
                            ConstantRow.typeVal = typeVal
                            parentKind = parentKind
                            parentIndex = parentIndex
                            valueIndex = valueIndex}|]
            | MetadataTableKind.CustomAttribute ->
                customAttributes <-
                    [|for _ in 1u .. rowCount do
                        let parentKind, parentIndex = readCodedIndex HasCustomAttribute
                        // The column called Type is slightly misleading
                        // it actually indexes a constructor method
                        // the owner of that constructor method is
                        //the Type of the Custom Attribute.
                        let typeKind, typeIndex = readCodedIndex CustomAttributeType
                        let valueIndex = readBlobHeapIndex ()

                        printfn
                            "CustomAttribute: parent=(%A, %i), type=(%A, %i), valueIndex=%i"
                            parentKind
                            parentIndex
                            typeKind
                            typeIndex
                            valueIndex

                        yield {
                            CustomAttributeRow.parentKind = parentKind
                            parentIndex = parentIndex
                            typeKind = typeKind
                            typeIndex = typeIndex
                            valueIndex = valueIndex}|]
            | MetadataTableKind.DeclSecurity ->
                declSecurities <-
                    [|for _ in 1u .. rowCount do
                        let action = br.ReadUInt16 ()
                        let parentKind, parentIndex = readCodedIndex HasDeclSecurity
                        let permissionSetIndex = readBlobHeapIndex ()

                        printfn
                            "DeclSecurity: action=%i, parent=(%A, %i), permissionSet=%i"
                            action
                            parentKind
                            parentIndex
                            permissionSetIndex

                        yield {
                            DeclSecurityRow.action = action
                            parentKind = parentKind
                            parentIndex = parentIndex
                            permissionSetIndex = permissionSetIndex}|]
            | MetadataTableKind.EventMap -> noImpl ()
            | MetadataTableKind.Event -> noImpl ()
            | MetadataTableKind.ExportedType -> noImpl ()
            | MetadataTableKind.Field ->
                fields <-
                    [|for _ in 1u .. rowCount do
                        let fieldAttrFlags = br.ReadUInt16 ()
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()

                        printfn "Field: flags=%X, name=%s, sigindex=%i" fieldAttrFlags name signatureIndex

                        yield {
                            FieldRow.fieldAttrFlags = fieldAttrFlags
                            name = name
                            signatureIndex = signatureIndex}|]
            | MetadataTableKind.FieldLayout -> noImpl ()
            | MetadataTableKind.FieldMarshal ->
                fieldMarshals <-
                    [|for _ in 1u .. rowCount do
                        let parentKind, parentIndex = readCodedIndex HasFieldMarshall
                        let nativeTypeIndex = readBlobHeapIndex ()

                        printfn "FieldMarshal: parent=(%A, %i), nativeType=%i" parentKind parentIndex nativeTypeIndex

                        yield {
                            FieldMarshalRow.parentKind = parentKind
                            parentIndex = parentIndex
                            nativeTypeIndex = nativeTypeIndex}|]
            | MetadataTableKind.FieldRVA ->
                fieldRVAs <-
                    [|for _ in 1u .. rowCount do
                        let rva = br.ReadUInt32 ()
                        let fieldIndex = readTableIndex MetadataTableKind.Field

                        printfn "FieldRVA: RVA=%i, fieldIndex=%i" rva fieldIndex

                        yield {
                            FieldRVARow.rva = rva
                            fieldIndex = fieldIndex}|]
            | MetadataTableKind.File -> noImpl ()
            | MetadataTableKind.GenericParam ->
                genericParams <-
                    [|for _ in 1u .. rowCount do
                        let number = br.ReadUInt16 ()
                        let flags = br.ReadUInt16 ()
                        let ownerKind, ownerIndex = readCodedIndex TypeOrMethodDef
                        let name = readHeapString ()

                        printfn
                            "GenericParam: number=%i, flags=0x%X, owner=(%A, %i), name=%s"
                            number
                            flags
                            ownerKind
                            ownerIndex
                            name

                        yield {
                            GenericParamRow.number = number
                            flags = flags
                            ownerKind = ownerKind
                            ownerIndex = ownerIndex
                            name = name}|]
            | MetadataTableKind.GenericParamConstraint ->
                genericParamConstraints <-
                    [|for _ in 1u .. rowCount do
                        let ownerIndex = readTableIndex MetadataTableKind.GenericParam
                        let constraintKind, constraintIndex = readCodedIndex TypeDefOrRef

                        printfn
                            "GenericParamConstraint: owner=%i, constraint=(%A, %i)"
                            ownerIndex
                            constraintKind
                            constraintIndex

                        yield {
                            GenericParamConstraintRow.ownerIndex = ownerIndex
                            constraintKind = constraintKind
                            constraintIndex = constraintIndex}|]
            | MetadataTableKind.ImplMap ->
                implMaps <-
                    [|for _ in 1u .. rowCount do
                        let mappingFlags = br.ReadUInt16 ()
                        //it only ever indexes the MethodDef table, since Field export is not supported
                        let memberForwardedKind, memberForwardedIndex = readCodedIndex MemberForwarded
                        let importName = readHeapString ()
                        let importScopeIndex = readTableIndex MetadataTableKind.ModuleRef

                        printfn
                            "ImplMap: forwarded=(%A, %i), importName=%s, importScopeIndex=%i"
                            memberForwardedKind
                            memberForwardedIndex
                            importName
                            importScopeIndex

                        yield {
                            ImplMapRow.mappingFlags = mappingFlags
                            memberForwardedKind = memberForwardedKind
                            memberForwardedIndex = memberForwardedIndex
                            importName = importName
                            importScopeIndex = importScopeIndex}|]
            | MetadataTableKind.InterfaceImpl ->
                interfaceImpls <-
                    [|for _ in 1u .. rowCount do
                        let classIndex = readTableIndex MetadataTableKind.TypeDef
                        let ifaceKind, ifaceIndex = readCodedIndex TypeDefOrRef

                        printfn "InterfaceImpl: class=%i, interface=(%A, %i)" classIndex ifaceKind ifaceIndex

                        yield {
                            InterfaceImplRow.classIndex = classIndex
                            ifaceKind = ifaceKind
                            ifaceIndex = ifaceIndex}|]
            | MetadataTableKind.ManifestResource ->
                manifestResources <-
                    [|for _ in 1u .. rowCount do
                        let offset = br.ReadUInt32 ()
                        let flags = br.ReadUInt32 ()
                        let name = readHeapString ()
                        let implKind, implIndex = readCodedIndex Implementation

                        printfn "ManifestResource: name=%s, impl=(%A, %i)" name implKind implIndex

                        yield {
                            ManifestResourceRow.offset = offset
                            flags = flags
                            name = name
                            implKind = implKind
                            implIndex = implIndex}|]
            | MetadataTableKind.MemberRef ->
                memberRefs <-
                    [|for _ in 1u .. rowCount do
                        let classKind, classIndex = readCodedIndex MemberRefParent
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()
                        
                        printfn "MemberRef: class=(%A, %i) name=%s, sigIndex=%i" classKind classIndex name signatureIndex

                        yield {
                            MemberRefRow.classKind = classKind
                            classIndex = classIndex
                            name = name
                            signatureIndex = signatureIndex}|]
            | MetadataTableKind.MethodDef ->
                methodDefs <-
                    [|for _ in 1u .. rowCount do
                        let rva = br.ReadUInt32 ()
                        let implFlags = br.ReadUInt16 ()
                        let flags = br.ReadUInt16 ()
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()
                        let paramIndex = readTableIndex MetadataTableKind.Param

                        printfn "MethodDef: name=%s, sigIndex=%i, paramIndex=%i" name signatureIndex paramIndex

                        yield {
                            MethodDefRow.rva = rva
                            implFlags = implFlags
                            flags = flags
                            name = name
                            signatureIndex = signatureIndex
                            paramIndex = paramIndex}|]
            | MetadataTableKind.MethodImpl ->
                methodImpls <-
                    [|for _ in 1u .. rowCount do
                        let classIndex = readTableIndex MetadataTableKind.TypeDef
                        let methodBodyKind, methodBodyIndex = readCodedIndex MethodDefOrRef
                        let methodDecKind, methodDecIndex = readCodedIndex MethodDefOrRef

                        printfn
                            "MethodImpl: class=%i, body=(%A, %i), declaration=(%A, %i)"
                            classIndex
                            methodBodyKind
                            methodBodyIndex
                            methodDecKind
                            methodDecIndex

                        yield {
                            MethodImplRow.classIndex = classIndex
                            methodBodyKind = methodBodyKind
                            methodBodyIndex = methodBodyIndex
                            methodDecKind = methodDecKind
                            methodDecIndex = methodDecIndex}|]
            | MetadataTableKind.MethodSemantics ->
                methodSemantics <-
                    [|for _ in 1u .. rowCount do
                        let semanticsFlags = br.ReadUInt16 ()
                        let methodIndex = readTableIndex MetadataTableKind.MethodDef
                        let assocKind, assocIndex = readCodedIndex HasSemantics

                        printfn
                            "MethodSemantics: semantics=%X, methodIndex=%i, assoc=(%A, %i)"
                            semanticsFlags
                            methodIndex
                            assocKind
                            assocIndex

                        yield {
                            MethodSemanticsRow.semanticsFlags = semanticsFlags
                            methodIndex = methodIndex
                            assocKind = assocKind
                            assocIndex = assocIndex}|]
            | MetadataTableKind.MethodSpec ->
                methodSpecs <-
                    [|for _ in 1u .. rowCount do
                        let methodKind, methodIndex = readCodedIndex MethodDefOrRef
                        let instIndex = readBlobHeapIndex ()

                        printfn "MethodSpec: method=(%A, %i), instantiation=%i" methodKind methodIndex instIndex

                        yield {
                            MethodSpecRow.methodKind = methodKind
                            methodIndex = methodIndex
                            instIndex = instIndex}|]
            | MetadataTableKind.Module ->
                modules <-
                    [|for _ in 1u .. rowCount do
                        readShortEq br 0us "module generation"
                        let name = readHeapString ()
                        let mvidIndex = readGUIDHeapIndex ()
                        let encIDIndex = readGUIDHeapIndex ()
                        let encBaseIdIndex = readGUIDHeapIndex ()
                        
                        printfn "module name=\"%s\"" name

                        yield {
                            ModuleRow.name = name
                            mvidIndex = mvidIndex
                            encIDIndex = encIDIndex
                            encBaseIdIndex = encBaseIdIndex}|]
            | MetadataTableKind.ModuleRef ->
                moduleRefs <-
                    [|for _ in 1u .. rowCount do
                        let name = readHeapString ()

                        printfn "ModuleRef: %s" name

                        yield {ModuleRefRow.name = name}|]
            | MetadataTableKind.NestedClass ->
                nestedClasses <-
                    [|for _ in 1u .. rowCount do
                        let nestedClassIndex = readTableIndex MetadataTableKind.TypeDef
                        let enclosingClassIndex = readTableIndex MetadataTableKind.TypeDef

                        printfn
                            "NestedClass: nestedClass=%i, enclosingClass=%i"
                            nestedClassIndex
                            enclosingClassIndex

                        yield {
                            NestedClassRow.nestedClassIndex = nestedClassIndex
                            enclosingClassIndex = enclosingClassIndex}|]
            | MetadataTableKind.Param ->
                paramRows <-
                    [|for _ in 1u .. rowCount do
                        let flags = br.ReadUInt16 ()
                        let sequence = br.ReadUInt16 ()
                        let name = readHeapString ()
                        
                        printfn "Param: name=\"%s\", seq=%i" name sequence

                        yield {
                            ParamRow.flags = flags
                            sequence = sequence
                            name = name}|]
            | MetadataTableKind.Property ->
                properties <-
                    [|for _ in 1u .. rowCount do
                        let flags = br.ReadUInt16 ()
                        let name = readHeapString ()
                        // The name of this column is misleading.  It does not index
                        // a TypeDef or TypeRef table. Instead it indexes the
                        // signature in the Blob heap of the Property
                        let typeIndex = readBlobHeapIndex ()

                        printfn "Property: name=%s, type=%i" name typeIndex

                        yield {
                            PropertyRow.flags = flags
                            name = name
                            typeIndex = typeIndex}|]
            | MetadataTableKind.PropertyMap ->
                propertyMaps <-
                    [|for _ in 1u .. rowCount do
                        let parentIndex = readTableIndex MetadataTableKind.TypeDef
                        let propertyListIndex = readTableIndex MetadataTableKind.Property

                        printfn "PropertyMap: parent=%i, propertyList=%i" parentIndex propertyListIndex

                        yield {
                            PropertyMapRow.parentIndex = parentIndex
                            propertyListIndex = propertyListIndex}|]
            | MetadataTableKind.StandAloneSig ->
                standAloneSigs <-
                    [|for _ in 1u .. rowCount do
                        let signatureIndex = readBlobHeapIndex ()
                        printfn "StandAloneSig: sigIndex=%i" signatureIndex

                        yield {StandAloneSigRow.signatureIndex = signatureIndex}|]
            | MetadataTableKind.TypeDef ->
                typeDefs <-
                    [|for _ in 1u .. rowCount do
                        let flags = br.ReadUInt32 ()
                        let typeName = readHeapString ()
                        let typeNamespace = readHeapString ()
                        let extendsKind, extendsIndex = readCodedIndex TypeDefOrRef
                        let fieldsIndex = readTableIndex MetadataTableKind.Field
                        let methodsIndex = readTableIndex MetadataTableKind.MethodDef

                        printfn "TypeDef: typeName=%s, typeNamespace=%s" typeName typeNamespace

                        yield {
                            TypeDefRow.flags = flags
                            typeName = typeName
                            typeNamespace = typeNamespace
                            extendsKind = extendsKind
                            extendsIndex = extendsIndex
                            fieldsIndex = fieldsIndex
                            methodsIndex = methodsIndex}|]
            | MetadataTableKind.TypeRef ->
                typeRefs <-
                    [|for _ in 1u .. rowCount do
                        let resolutionScopeKind, resolutionScopeIndex = readCodedIndex ResolutionScope
                        let typeName = readHeapString ()
                        let typeNamespace = readHeapString ()

                        printfn
                            "TypeRef: resolutionScope=(%A, %i), typeName=%s, typeNamespace=%s"
                            resolutionScopeKind
                            resolutionScopeIndex
                            typeName
                            typeNamespace

                        yield {
                            TypeRefRow.resolutionScopeKind = resolutionScopeKind
                            resolutionScopeIndex = resolutionScopeIndex
                            typeName = typeName
                            typeNamespace = typeNamespace}|]
            | MetadataTableKind.TypeSpec ->
                typeSpecs <-
                    [|for _ in 1u .. rowCount do
                        let sigIndex = readBlobHeapIndex ()
                        printfn "TypeSpec: %i" sigIndex

                        yield {TypeSpecRow.sigIndex = sigIndex}|]
            | _ -> noImpl ()

        {
            MetadataTables.assemblies = assemblies
            assemblyRefs = assemblyRefs
            classLayouts = classLayouts
            constants = constants
            customAttributes = customAttributes
            declSecurities = declSecurities
            fields = fields
            fieldMarshals = fieldMarshals
            fieldRVAs = fieldRVAs
            genericParams = genericParams
            genericParamConstraints = genericParamConstraints
            implMaps = implMaps
            interfaceImpls = interfaceImpls
            manifestResources = manifestResources
            memberRefs = memberRefs
            methodDefs = methodDefs
            methodImpls = methodImpls
            methodSemantics = methodSemantics
            methodSpecs = methodSpecs
            modules = modules
            moduleRefs = moduleRefs
            nestedClasses = nestedClasses
            paramRows = paramRows
            properties = properties
            propertyMaps = propertyMaps
            standAloneSigs = standAloneSigs
            typeDefs = typeDefs
            typeRefs = typeRefs
            typeSpecs = typeSpecs
        }

