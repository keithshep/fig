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

type MetadataTables =
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
    [|for x in System.Enum.GetValues typeof<MetadataTables> ->
        enum<MetadataTables> (x :?> int)|]

let isMetadataTableValid (validTblBits : uint64) (mt : MetadataTables) =
    (1uL <<< int mt) &&& validTblBits <> 0uL

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
    | TypeDefOrRef -> [|MetadataTables.TypeDef; MetadataTables.TypeRef; MetadataTables.TypeSpec|]
    | HasConstant -> [|MetadataTables.Field; MetadataTables.Param; MetadataTables.Property|]
    | HasCustomAttribute ->
        [|MetadataTables.MethodDef; MetadataTables.Field; MetadataTables.TypeRef;
          MetadataTables.TypeDef; MetadataTables.Param; MetadataTables.InterfaceImpl;
          MetadataTables.MemberRef; MetadataTables.Module;
          (* TODO documented as Permission not sure if this is valid *) MetadataTables.DeclSecurity;
          MetadataTables.Property; MetadataTables.Event; MetadataTables.StandAloneSig;
          MetadataTables.ModuleRef; MetadataTables.TypeSpec; MetadataTables.Assembly;
          MetadataTables.AssemblyRef; MetadataTables.File; MetadataTables.ExportedType;
          MetadataTables.ManifestResource; MetadataTables.GenericParam;
          MetadataTables.GenericParamConstraint; MetadataTables.MethodSpec|]
    | HasFieldMarshall -> [|MetadataTables.Field; MetadataTables.Param|]
    | HasDeclSecurity -> [|MetadataTables.TypeDef; MetadataTables.MethodDef; MetadataTables.Assembly|]
    | MemberRefParent ->
        [|MetadataTables.TypeDef; MetadataTables.TypeRef; MetadataTables.ModuleRef;
          MetadataTables.MethodDef; MetadataTables.TypeSpec|]
    | HasSemantics -> [|MetadataTables.Event; MetadataTables.Property|]
    | MethodDefOrRef -> [|MetadataTables.MethodDef; MetadataTables.MemberRef|]
    | MemberForwarded -> [|MetadataTables.Field; MetadataTables.MethodDef|]
    | Implementation -> [|MetadataTables.File; MetadataTables.AssemblyRef; MetadataTables.ExportedType|]
    | CustomAttributeType -> [|MetadataTables.MethodDef; MetadataTables.MemberRef|]
    | ResolutionScope ->
        [|MetadataTables.Module; MetadataTables.ModuleRef;
          MetadataTables.AssemblyRef; MetadataTables.TypeRef|]
    | TypeOrMethodDef -> [|MetadataTables.TypeDef; MetadataTables.MethodDef|]

let resolveTableKind (cik : CodedIndexKind) (i : int) =
    match cik with
    | CustomAttributeType ->
        // CustomAttributeType is a special case since it isn't directly indexable
        match i with
        | 2 -> MetadataTables.MethodDef
        | 3 -> MetadataTables.MemberRef
        | _ -> failwith (sprintf "bad index used for CustomAttributeType: %i" i)

    | _ -> (possibleTableKinds cik).[i]

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

        printfn "num tables: %i" rowCounts.Count
        for kv in rowCounts do printfn "%A, %A is wide? %A" kv.Key kv.Value (tableIndicesWide kv.Key)
        
        for kv in rowCounts do
            let rowCount = kv.Value
            let noImpl () = failwith (sprintf "no implementation for %A" kv.Key)
            match kv.Key with
            | MetadataTables.Assembly ->
                for i in {1u .. rowCount} do
                    let hashAlgId = br.ReadUInt32 ()
                    let majorVersion = br.ReadUInt16 ()
                    let minorVersion = br.ReadUInt16 ()
                    let buildNumber = br.ReadUInt16 ()
                    let revisionNumber = br.ReadUInt16 ()
                    let flags = br.ReadUInt32 ()
                    let pubKeyBlobIdx = readBlobHeapIndex ()
                    let name = readHeapString ()
                    let culture = readHeapString ()
                    
                    printfn "asm name=\"%s\", culture=\"%s\"" name culture
            | MetadataTables.AssemblyOS -> noImpl ()
            | MetadataTables.AssemblyProcessor -> noImpl ()
            | MetadataTables.AssemblyRef ->
                for i in {1u .. rowCount} do
                    let majorVersion = br.ReadUInt16 ()
                    let minorVersion = br.ReadUInt16 ()
                    let buildNumber = br.ReadUInt16 ()
                    let revisionNumber = br.ReadUInt16 ()
                    let flags = br.ReadUInt32 ()
                    let publicKeyOrTokenIndex = readBlobHeapIndex ()
                    let name = readHeapString ()
                    let culture = readHeapString ()
                    let hashValueIndex = readBlobHeapIndex ()
                    
                    printfn "refasm name=\"%s\", culture=\"%s\"" name culture
            | MetadataTables.AssemblyRefOS
            | MetadataTables.AssemblyRefProcessor
            | MetadataTables.ClassLayout
            | MetadataTables.Constant
            | MetadataTables.CustomAttribute
            | MetadataTables.DeclSecurity
            | MetadataTables.EventMap
            | MetadataTables.Event
            | MetadataTables.ExportedType -> noImpl ()
            | MetadataTables.Field ->
                for i in {1u .. rowCount} do
                    let fieldAttrFlags = br.ReadUInt16 ()
                    let name = readHeapString ()
                    let signatureIndex = readBlobHeapIndex ()

                    printfn "Field: flags=%X, name=%s, sigindex=%i" fieldAttrFlags name signatureIndex
            | MetadataTables.FieldLayout
            | MetadataTables.FieldMarshal
            | MetadataTables.FieldRVA
            | MetadataTables.File
            | MetadataTables.GenericParam
            | MetadataTables.GenericParamConstraint
            | MetadataTables.ImplMap
            | MetadataTables.InterfaceImpl
            | MetadataTables.ManifestResource
            | MetadataTables.MemberRef
            | MetadataTables.MethodDef
            | MetadataTables.MethodImpl
            | MetadataTables.MethodSemantics
            | MetadataTables.MethodSpec -> noImpl ()
            | MetadataTables.Module ->
                for i in {1u .. rowCount} do
                    readShortEq br 0us "module generation"
                    let name = readHeapString ()
                    let mvidIndex = readGUIDHeapIndex ()
                    let encIDIndex = readGUIDHeapIndex ()
                    let encBaseIdIndex = readGUIDHeapIndex ()
                    
                    printfn "module name=\"%s\"" name
            | MetadataTables.ModuleRef
            | MetadataTables.NestedClass
            | MetadataTables.Param
            | MetadataTables.Property
            | MetadataTables.PropertyMap
            | MetadataTables.StandAloneSig -> noImpl ()
            | MetadataTables.TypeDef ->
                for i in {1u .. rowCount} do
                    let flags = br.ReadUInt32 ()
                    let typeName = readHeapString ()
                    let typeNamespace = readHeapString ()
                    let extendsKind, extendsIndex = readCodedIndex TypeDefOrRef
                    let fieldsIndex = readTableIndex MetadataTables.Field
                    let methodsIndex = readTableIndex MetadataTables.MethodDef

                    printfn "TypeDef: typeName=%s, typeNamespace=%s" typeName typeNamespace
            | MetadataTables.TypeRef ->
                for i in {1u .. rowCount} do
                    let tableKind, rowIndex = readCodedIndex ResolutionScope
                    let typeName = readHeapString ()
                    let typeNamespace = readHeapString ()

                    printfn "TypeRef: tableKind=%A, typeName=%s, typeNamespace=%s" tableKind typeName typeNamespace
            | MetadataTables.TypeSpec
            | _ -> noImpl ()


