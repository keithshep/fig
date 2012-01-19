module Fig.AssemblyParser

open Fig.IOUtil
open Fig.ParseCode

open System.IO

// see EMCA-335 25.2.1
let readMSDOSHeader (r : BinaryReader) =
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
    readBytesEq r prePEOffsetBytes "pre-PE offset"
    
    let peOffset = r.ReadUInt32 ()
    
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
    readBytesEq r postPEOffsetBytes "post-PE offset"

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
    | None -> failwithf "failed to locate RVA 0x%X" r

// specified in EMCA-335 25.2.2
let readPEHeader (r : BinaryReader) =
    let peOffset = readMSDOSHeader r
    r.BaseStream.Seek (int64 peOffset, SeekOrigin.Begin) |> ignore
    
    readBytesEq r [|byte 'P'; byte 'E'; 0uy; 0uy|] "PE header start"
    readShortEq r 0x014Cus "machine"

    let numSections = r.ReadUInt16 ()
    let timeStampSecs = r.ReadUInt32 ()

    readIntEq r 0u "pointer to symbol table"
    readIntEq r 0u "number of symbols"

    let optHeaderSize = r.ReadUInt16 ()
    if not (optHeaderSize = 0us || optHeaderSize = 224us) then
        failwith "expected optional header size to be 0 or 224"

    let currByte = r.ReadByte ()
    if 0x01uy &&& currByte <> 0x00uy then
        failwith "IMAGE_FILE_RELOCS_STRIPPED expected to be unset"
    if 0x02uy &&& currByte = 0x00uy then
        failwith "IMAGE_FILE_EXECUTABLE_IMAGE expected to be set"

    let currByte = r.ReadByte ()
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
            readShortEq r 0x010Bus "magic"
            readByteEq r 0x06uy "LMajor"
            readByteEq r 0x00uy "LMinor"
            let codeSize = r.ReadUInt32 ()
            let initDataSize = r.ReadUInt32 ()
            let uninitDataSize = r.ReadUInt32 ()
            let entryPointRVA = r.ReadUInt32 ()
            let baseOfCode = r.ReadUInt32 ()
            let baseOfData = r.ReadUInt32 ()

            // 25.2.3.2 NT specific fields
            let imageBase = r.ReadUInt32 ()
            if imageBase &&& 0x0000FFFFu <> 0u then
                failwith "image base should be a multiple of 0x10000"
            let sectionAlignment = r.ReadUInt32 ()
            let fileAlignment = r.ReadUInt32 ()
            if fileAlignment <> 0x00000200u then
                failwith "file alignment expected to be 0x200"
            readShortEq r 5us "OS Major"
            readShortEq r 0us "OS Minor"
            readShortEq r 0us "User Major"
            readShortEq r 0us "User Minor"
            readShortEq r 5us "SubSys Major"
            readShortEq r 0us "SubSys Minor"
            readIntEq r 0u "reserved"
            let imageSize = r.ReadUInt32 ()
            if imageSize % sectionAlignment <> 0u then
                printfn "image size expected to be a multiple of section alignment"
            let headerSize = r.ReadUInt32 ()
            if headerSize % fileAlignment <> 0u then
                printfn "header size expected to be a multiple of file alignment"
            readIntEq r 0u "file checksum"
            let subSystem =
                match r.ReadUInt16 () with
                | 0x0003us -> WindowsCUI
                | 0x0002us -> WindowsGUI
                | i -> failwithf "unexpected sub-system 0x%X" i
            let dllFlags = r.ReadUInt16 ()
            if dllFlags &&& 0x100Fus <> 0us then
                failwith "expected DLL flags to be 0 for mask 0x100F"
            readIntEq r 0x00100000u "stack reserve size"
            readIntEq r 0x00001000u "stack commit size"
            readIntEq r 0x00100000u "heap reserve size"
            readIntEq r 0x00001000u "heap commit size"
            readIntEq r 0x00000000u "loader flags"
            readIntEq r 0x00000010u "number of data directories"

            // 25.2.3.3 PE header data directories
            readLongEq r 0uL "export table"
            let importTableRVA = r.ReadUInt32 ()
            let importTableSize = r.ReadUInt32 ()
            //r.PushPos (int64 importTableRVA)
            //printfn "importtbl rva %i 0x%X and size %i 0x%X" importTableRVA importTableRVA importTableSize importTableSize
            //readImportTables r |> ignore
            //printfn "READ"
            //r.PopPos ()
            //printfn "POPPED"
            readLongEq r 0uL "resource table"
            readLongEq r 0uL "exception table"
            readLongEq r 0uL "certificate table"
            let baseRelocationRVA = r.ReadUInt32 ()
            let baseRelocationSize = r.ReadUInt32 ()
            readLongEq r 0uL "debug"
            readLongEq r 0uL "copyright"
            readLongEq r 0uL "global ptr"
            readLongEq r 0uL "tls table"
            readLongEq r 0uL "load config table"
            readLongEq r 0uL "bound import table"
            let importAddressTableRVA = r.ReadUInt32 ()
            let importAddressTableSize = r.ReadUInt32 ()
            readLongEq r 0uL "delay import descriptor"
            let cliHeaderRVA = r.ReadUInt32 ()
            let cliHeaderSize = r.ReadUInt32 ()
            //printfn "CLI header: %i %i" cliHeaderRVA cliHeaderSize
            readLongEq r 0uL "reserved"
            Some {
                // 25.2.3.1 standard fields
                PEOptionalHeader.codeSize = codeSize
                initDataSize = initDataSize
                uninitDataSize = uninitDataSize
                entryPointRVA = entryPointRVA
                baseOfCode = baseOfCode
                baseOfData = baseOfData

                // 25.2.3.2 NT specific fields
                imageBase = imageBase
                sectionAlignment = sectionAlignment
                fileAlignment = fileAlignment
                imageSize = imageSize
                headerSize = headerSize
                subSystem = subSystem
                dllFlags = dllFlags

                // 25.2.3.3 PE header data directories
                importTableRVA = importTableRVA
                importTableSize = importTableSize
                baseRelocationRVA = baseRelocationRVA
                baseRelocationSize = baseRelocationSize
                importAddressTableRVA = importAddressTableRVA
                importAddressTableSize = importAddressTableSize
                cliHeaderRVA = cliHeaderRVA
                cliHeaderSize = cliHeaderSize}

    // return the PE header
    {
        PEHeader.numSections = numSections
        timeStampSecs = timeStampSecs
        is32BitMachine = is32BitMachine
        isDLL = isDLL
        optHeader = optHeader
    }

// specified in EMCA-335 25.3
let readSectionHeader (r : BinaryReader) =
    let name = readFixedASCII r 8
    let virtualSize = r.ReadUInt32 ()
    let virtualAddr = r.ReadUInt32 ()
    let sizeOfRawData = r.ReadUInt32 ()
    let ptrToRawData = r.ReadUInt32 ()
    readIntEq r 0u "PointerToRelocations"
    readIntEq r 0u "PointerToLinenumbers"
    readShortEq r 0us "NumberOfRelocations"
    readShortEq r 0us "NumberOfLinenumbers"
    let currByte = r.ReadByte ()
    let containsCode = currByte &&& 0x20uy <> 0x00uy
    let containsInitData = currByte &&& 0x40uy <> 0x00uy
    let containsUninitData = currByte &&& 0x80uy <> 0x00uy
    r.BaseStream.Seek (2L, SeekOrigin.Current) |> ignore
    let currByte = r.ReadByte ()
    let memExec = currByte &&& 0x20uy <> 0x00uy
    let memRead = currByte &&& 0x40uy <> 0x00uy
    let memWrite = currByte &&& 0x80uy <> 0x00uy
    
    {
        SectionHeader.name = name
        virtSize = virtualSize
        virtAddr = virtualAddr
        sizeOfRawData = sizeOfRawData
        ptrToRawData = ptrToRawData
        containsCode = containsCode
        containsInitData = containsInitData
        containsUninitData = containsUninitData
        memExec = memExec
        memRead = memRead
        memWrite = memWrite
    }

let readSectionHeaders (r : BinaryReader) (pe : PEHeader) =
    [for _ in 1us .. pe.numSections -> readSectionHeader r]

// 25.3.3 CLI Header
let readCLIHeader (r : BinaryReader) (secHdrs : SectionHeader list) (peHdr : PEHeader) =
    match peHdr.optHeader with
    | None -> failwith "can't read CLI with missing optional PE header"
    | Some {cliHeaderRVA = rvi} ->
        r.BaseStream.Seek (rvaToDiskPos secHdrs rvi, SeekOrigin.Begin) |> ignore
        readIntEq r 72u "size in bytes"
        let majorRuntimeVersion = r.ReadUInt16 ()
        let minorRuntimeVersion = r.ReadUInt16 ()
        let metaDataRVA = r.ReadUInt32 ()
        let metaDataSize = r.ReadUInt32 ()
        let flags = r.ReadUInt32 ()
        let entryPointTok = r.ReadUInt32 ()
        printfn "entry point tok: %i" entryPointTok
        let resourcesRVA = r.ReadUInt32 ()
        let resourcesSize = r.ReadUInt32 ()
        let strongNameSig = r.ReadUInt64 ()
        readLongEq r 0uL "code manager table"
        let vTableFixupsRVA = r.ReadUInt32 ()
        let vTableFixupsSize = r.ReadUInt32 ()
        readLongEq r 0uL "export address table jumps"
        readLongEq r 0uL "managed native header"
        
        {
            CLIHeader.majorRuntimeVersion = majorRuntimeVersion
            minorRuntimeVersion = minorRuntimeVersion
            metaDataRVA = metaDataRVA
            metaDataSize = metaDataSize
            flags = flags
            entryPointTok = entryPointTok
            resourcesRVA = resourcesRVA
            resourcesSize = resourcesSize
            strongNameSig = strongNameSig
            vTableFixupsRVA = vTableFixupsRVA
            vTableFixupsSize = vTableFixupsSize
        }

let readStreamHeader (r : BinaryReader) =
    let offset = r.ReadUInt32 ()
    let size = r.ReadUInt32 ()
    let name = readAlignedASCII r 4
    (offset, size, name)

let readStreamHeaders (r : BinaryReader) (secHdrs : SectionHeader list) (cliHeader : CLIHeader) =
    r.BaseStream.Seek (rvaToDiskPos secHdrs cliHeader.metaDataRVA, SeekOrigin.Begin) |> ignore
    readIntEq r 0x424A5342u "magic signature for physical metadata"
    r.BaseStream.Seek (4L, SeekOrigin.Current) |> ignore
    readIntEq r 0u "reserved"
    let versionStrLen = r.ReadUInt32 ()
    let tempPos = r.BaseStream.Position
    printfn "version string: \"%s\", alloc: %i" (readASCII r) versionStrLen
    r.BaseStream.Seek (tempPos + int64 versionStrLen, SeekOrigin.Begin) |> ignore
    readShortEq r 0us "meta data flags"
    let numStreams = r.ReadUInt16 ()
    printfn "num streams %i" numStreams
    
    Map.ofList
        [for _ in 1us .. numStreams do
            let offset, size, name = readStreamHeader r
            printfn "offset = %i, size = %i, name = \"%s\"" offset size name
            yield (name, (offset, size))]

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

    if maskedBits <> 0uL then failwithf "bad bits: 0x%X" maskedBits

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
    with
        member x.BitCount =
            match x with
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

        member x.PossibleTableKinds =
            match x with
            | TypeDefOrRef -> [|MetadataTableKind.TypeDefKind; MetadataTableKind.TypeRefKind; MetadataTableKind.TypeSpecKind|]
            | HasConstant -> [|MetadataTableKind.FieldKind; MetadataTableKind.ParamKind; MetadataTableKind.PropertyKind|]
            | HasCustomAttribute ->
                [|MetadataTableKind.MethodDefKind; MetadataTableKind.FieldKind; MetadataTableKind.TypeRefKind;
                  MetadataTableKind.TypeDefKind; MetadataTableKind.ParamKind; MetadataTableKind.InterfaceImplKind;
                  MetadataTableKind.MemberRefKind; MetadataTableKind.ModuleKind;
                  (* TODO documented as Permission not sure if this is valid *) MetadataTableKind.DeclSecurityKind;
                  MetadataTableKind.PropertyKind; MetadataTableKind.EventKind; MetadataTableKind.StandAloneSigKind;
                  MetadataTableKind.ModuleRefKind; MetadataTableKind.TypeSpecKind; MetadataTableKind.AssemblyKind;
                  MetadataTableKind.AssemblyRefKind; MetadataTableKind.FileKind; MetadataTableKind.ExportedTypeKind;
                  MetadataTableKind.ManifestResourceKind; MetadataTableKind.GenericParamKind;
                  MetadataTableKind.GenericParamConstraintKind; MetadataTableKind.MethodSpecKind|]
            | HasFieldMarshall -> [|MetadataTableKind.FieldKind; MetadataTableKind.ParamKind|]
            | HasDeclSecurity -> [|MetadataTableKind.TypeDefKind; MetadataTableKind.MethodDefKind; MetadataTableKind.AssemblyKind|]
            | MemberRefParent ->
                [|MetadataTableKind.TypeDefKind; MetadataTableKind.TypeRefKind; MetadataTableKind.ModuleRefKind;
                  MetadataTableKind.MethodDefKind; MetadataTableKind.TypeSpecKind|]
            | HasSemantics -> [|MetadataTableKind.EventKind; MetadataTableKind.PropertyKind|]
            | MethodDefOrRef -> [|MetadataTableKind.MethodDefKind; MetadataTableKind.MemberRefKind|]
            | MemberForwarded -> [|MetadataTableKind.FieldKind; MetadataTableKind.MethodDefKind|]
            | Implementation -> [|MetadataTableKind.FileKind; MetadataTableKind.AssemblyRefKind; MetadataTableKind.ExportedTypeKind|]
            | CustomAttributeType -> [|MetadataTableKind.MethodDefKind; MetadataTableKind.MemberRefKind|]
            | ResolutionScope ->
                [|MetadataTableKind.ModuleKind; MetadataTableKind.ModuleRefKind;
                  MetadataTableKind.AssemblyRefKind; MetadataTableKind.TypeRefKind|]
            | TypeOrMethodDef -> [|MetadataTableKind.TypeDefKind; MetadataTableKind.MethodDefKind|]

        member x.ResolveTableKind (i : int) =
            match x with
            | CustomAttributeType ->
                // CustomAttributeType is a special case since it isn't directly indexable
                match i with
                | 2 -> MetadataTableKind.MethodDefKind
                | 3 -> MetadataTableKind.MemberRefKind
                | _ -> failwithf "bad index used for CustomAttributeType: %i" i

            | _ -> x.PossibleTableKinds.[i]

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

type EventMapRow = {
    parentTypeDefIndex : uint32
    eventStartIndex : uint32}

type EventRow = {
    eventFlags : uint16
    name : string
    eventTypeKind : MetadataTableKind
    eventTypeIndex : uint32}

type FieldRow = {
    fieldAttrFlags : uint16
    name : string
    signatureIndex : uint32}

type FieldLayoutRow = {
    offset : uint32
    fieldIndex : uint32}

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
    eventMap : EventMapRow array
    events : EventRow array
    fields : FieldRow array
    fieldLayouts : FieldLayoutRow array
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
        (r : PosStackBinaryReader)
        (secHdrs : SectionHeader list)
        (cliHeader : CLIHeader)
        (streamHeaders : Map<string, uint32 * uint32>) =

    // see 24.2.6
    match streamHeaders.TryFind "#~" with
    | None -> failwith "failed to find the \"#~\" stream"
    | Some (tildeOffset, tildeSize) ->
        let rraToDiskPos rootRelAddr =
            rvaToDiskPos secHdrs (cliHeader.metaDataRVA + rootRelAddr)
        r.BaseStream.Seek (rraToDiskPos tildeOffset, SeekOrigin.Begin) |> ignore
        
        readIntEq r 0u "meta tables header reserved field"
        readByteEq r 2uy "major version of table schemata"
        readByteEq r 0uy "minor version of table schemata"
        let heapSizes = r.ReadByte ()
        readByteEq r 1uy "meta tables header second reserved field"
        let validTables = r.ReadUInt64 ()
        assertTableBitsValid validTables
        let sortedTables = r.ReadUInt64 ()

        let readMaybeWideIndex isWide =
            if isWide then
                r.ReadUInt32 ()
            else
                r.ReadUInt16 () |> uint32

        let stringHeapIndicesWide = heapSizes &&& 0x01uy <> 0x00uy
        let readStringHeapIndex () = readMaybeWideIndex stringHeapIndicesWide
        let readHeapString () =
            let i = readStringHeapIndex ()
            let strOffset =
                match streamHeaders.TryFind "#Strings" with
                | Some (offset, _) -> offset
                | None -> failwith "failed to find string section"
            let strAddr = rraToDiskPos strOffset + int64 i
            r.PushPos strAddr
            let str = readUTF8 r
            r.PopPos ()
            str

        let guidHeapIndicesWide = heapSizes &&& 0x02uy <> 0x00uy
        let readGUIDHeapIndex () = readMaybeWideIndex guidHeapIndicesWide

        let blobHeapIndicesWide = heapSizes &&& 0x04uy <> 0x00uy
        let readBlobHeapIndex () = readMaybeWideIndex blobHeapIndicesWide

        let rowCounts =
            Map.ofList
                [for mt in sortedTableEnums do
                    if isMetadataTableValid validTables mt then
                        yield mt, r.ReadUInt32 ()]

        let tableIndicesWide mt =
            match rowCounts.TryFind mt with
            | None -> false
            | Some count -> count &&& 0xFFFF0000u <> 0u

        let readTableIndex mt =
            if tableIndicesWide mt then
                r.ReadUInt32 ()
            else
                r.ReadUInt16 () |> uint32

        let tableIndexWidth mt = if tableIndicesWide mt then 4L else 2L

        let codedIndicesWide (cik : CodedIndexKind) =
            let maxCount =
                let allCounts =
                    [|for mt in cik.PossibleTableKinds do
                        match rowCounts.TryFind mt with
                        | None -> ()
                        | Some x -> yield x|]
                if Array.isEmpty allCounts then 0u else Array.max allCounts
            let mask = 0xFFFF0000u ||| (0xFFFF0000u >>> cik.BitCount)
            maxCount &&& mask <> 0u

        let readCodedIndex (cik : CodedIndexKind) =
            let rawIndex =
                if codedIndicesWide cik then
                    r.ReadUInt32 ()
                else
                    r.ReadUInt16 () |> uint32
            let cbc = cik.BitCount
            let tableKindIndex = int (rawIndex &&& ~~~(0xFFFFFFFFu <<< cbc))
            let tableKind = cik.ResolveTableKind tableKindIndex
            let rowIndex = rawIndex >>> cbc
            
            tableKind, rowIndex

        let mutable assemblies = ([||] : AssemblyRow array)
        let mutable assemblyRefs = ([||] : AssemblyRefRow array)
        let mutable classLayouts = ([||] : ClassLayoutRow array)
        let mutable constants = ([||] : ConstantRow array)
        let mutable customAttributes = ([||] : CustomAttributeRow array)
        let mutable declSecurities = ([||] : DeclSecurityRow array)
        let mutable eventMap = ([||] : EventMapRow array)
        let mutable events = ([||] : EventRow array)
        let mutable fields = ([||] : FieldRow array)
        let mutable fieldLayouts = ([||] : FieldLayoutRow array)
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
            printfn "MetadataTableKind=%A" kv.Key
            let rowCount = kv.Value
            let noImpl () = failwithf "no implementation for %A" kv.Key
            match kv.Key with
            | MetadataTableKind.AssemblyKind ->
                assemblies <-
                    [|for _ in 1u .. rowCount do
                        let hashAlgId = r.ReadUInt32 ()
                        let majorVersion = r.ReadUInt16 ()
                        let minorVersion = r.ReadUInt16 ()
                        let buildNumber = r.ReadUInt16 ()
                        let revisionNumber = r.ReadUInt16 ()
                        let flags = r.ReadUInt32 ()
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
            | MetadataTableKind.AssemblyOSKind ->
                printfn "AssemblyOS: skipping %i rows..." rowCount
                let tableSize = 4L * 3L
                r.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyProcessorKind ->
                printfn "AssemblyProcessorKind: skipping %i rows..." rowCount
                let tableSize = 4L
                r.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyRefKind ->
                assemblyRefs <-
                    [|for _ in 1u .. rowCount do
                        let majorVersion = r.ReadUInt16 ()
                        let minorVersion = r.ReadUInt16 ()
                        let buildNumber = r.ReadUInt16 ()
                        let revisionNumber = r.ReadUInt16 ()
                        let flags = r.ReadUInt32 ()
                        let publicKeyOrTokenIndex = readBlobHeapIndex ()
                        let name = readHeapString ()
                        let culture = readHeapString ()
                        let hashValueIndex = readBlobHeapIndex ()
                        
                        printfn "AssemblyRefKind: name=\"%s\", culture=\"%s\"" name culture

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
            | MetadataTableKind.AssemblyRefOSKind ->
                printfn "AssemblyRefOSKind: skipping %i rows..." rowCount
                let tableSize = 4L * 3L + tableIndexWidth MetadataTableKind.AssemblyRefKind
                r.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyRefProcessorKind ->
                printfn "AssemblyRefProcessorKind: skipping %i rows..." rowCount
                let tableSize = 4L + tableIndexWidth MetadataTableKind.AssemblyRefKind
                r.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.ClassLayoutKind ->
                classLayouts <-
                    [|for _ in 1u .. rowCount do
                        let packingSize = r.ReadUInt16 ()
                        let classSize = r.ReadUInt32 ()
                        let parentIndex = readTableIndex MetadataTableKind.TypeDefKind

                        printfn "ClassLayoutKind: packingSize=%i, classSize=%i, parent=%i" packingSize classSize parentIndex

                        yield {
                            ClassLayoutRow.packingSize = packingSize
                            classSize = classSize
                            parentIndex = parentIndex}|]
            | MetadataTableKind.ConstantKind ->
                constants <-
                    [|for _ in 1u .. rowCount do
                        let typeVal = r.ReadByte ()
                        readByteEq r 0x00uy "constant type padding"
                        let parentKind, parentIndex = readCodedIndex HasConstant
                        let valueIndex = readBlobHeapIndex ()

                        printfn "ConstantKind: type=0x0x%X, parent=(%A, %i), value=%i" typeVal parentKind parentIndex valueIndex

                        yield {
                            ConstantRow.typeVal = typeVal
                            parentKind = parentKind
                            parentIndex = parentIndex
                            valueIndex = valueIndex}|]
            | MetadataTableKind.CustomAttributeKind ->
                customAttributes <-
                    [|for _ in 1u .. rowCount do
                        let parentKind, parentIndex = readCodedIndex HasCustomAttribute
                        // The column called Type is slightly misleading
                        // it actually indexes a constructor method
                        // the owner of that constructor method is
                        // the Type of the Custom Attribute.
                        let typeKind, typeIndex = readCodedIndex CustomAttributeType
                        let valueIndex = readBlobHeapIndex ()

                        printfn
                            "CustomAttributeKind: parent=(%A, %i), type=(%A, %i), valueIndex=%i"
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
            | MetadataTableKind.DeclSecurityKind ->
                declSecurities <-
                    [|for _ in 1u .. rowCount do
                        let action = r.ReadUInt16 ()
                        let parentKind, parentIndex = readCodedIndex HasDeclSecurity
                        let permissionSetIndex = readBlobHeapIndex ()

                        printfn
                            "DeclSecurityKind: action=%i, parent=(%A, %i), permissionSet=%i"
                            action
                            parentKind
                            parentIndex
                            permissionSetIndex

                        yield {
                            DeclSecurityRow.action = action
                            parentKind = parentKind
                            parentIndex = parentIndex
                            permissionSetIndex = permissionSetIndex}|]
            | MetadataTableKind.EventMapKind ->
                eventMap <-
                    [|for _ in 1u .. rowCount do
                        let parentTypeDefIndex = readTableIndex MetadataTableKind.TypeDefKind
                        let eventStartIndex = readTableIndex MetadataTableKind.EventKind

                        printfn
                            "EventMapKind: parent=%i, eventStart=%i"
                            parentTypeDefIndex
                            eventStartIndex

                        yield {
                            EventMapRow.parentTypeDefIndex = parentTypeDefIndex
                            eventStartIndex = eventStartIndex}|]
            | MetadataTableKind.EventKind ->
                events <-
                    [|for _ in 1u .. rowCount do
                        let eventFlags = r.ReadUInt16()
                        let name = readHeapString()
                        let eventTypeKind, eventTypeIndex = readCodedIndex TypeDefOrRef

                        printfn
                            "EventKind: flags=0x%X, name=%s, eventType=(%A, %i)"
                            eventFlags
                            name
                            eventTypeKind
                            eventTypeIndex

                        yield {
                            EventRow.eventFlags = eventFlags
                            name = name
                            eventTypeKind = eventTypeKind
                            eventTypeIndex = eventTypeIndex}|]
            | MetadataTableKind.ExportedTypeKind -> noImpl ()
            | MetadataTableKind.FieldKind ->
                fields <-
                    [|for _ in 1u .. rowCount do
                        let fieldAttrFlags = r.ReadUInt16 ()
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()

                        printfn "FieldKind: flags=0x%X, name=\"%s\", sigindex=%i" fieldAttrFlags name signatureIndex

                        yield {
                            FieldRow.fieldAttrFlags = fieldAttrFlags
                            name = name
                            signatureIndex = signatureIndex}|]
            | MetadataTableKind.FieldLayoutKind ->
                fieldLayouts <-
                    [|for _ in 1u .. rowCount do
                        let offset = r.ReadUInt32()
                        let fieldIndex = readTableIndex MetadataTableKind.FieldKind

                        printfn "FieldLayout: offset=%i, fieldIndex=%i" offset fieldIndex

                        yield {
                            FieldLayoutRow.offset = offset
                            fieldIndex = fieldIndex}|]
            | MetadataTableKind.FieldMarshalKind ->
                fieldMarshals <-
                    [|for _ in 1u .. rowCount do
                        let parentKind, parentIndex = readCodedIndex HasFieldMarshall
                        let nativeTypeIndex = readBlobHeapIndex ()

                        printfn "FieldMarshalKind: parent=(%A, %i), nativeType=%i" parentKind parentIndex nativeTypeIndex

                        yield {
                            FieldMarshalRow.parentKind = parentKind
                            parentIndex = parentIndex
                            nativeTypeIndex = nativeTypeIndex}|]
            | MetadataTableKind.FieldRVAKind ->
                fieldRVAs <-
                    [|for _ in 1u .. rowCount do
                        let rva = r.ReadUInt32 ()
                        let fieldIndex = readTableIndex MetadataTableKind.FieldKind

                        printfn "FieldRVAKind: RVA=%i, fieldIndex=%i" rva fieldIndex

                        yield {
                            FieldRVARow.rva = rva
                            fieldIndex = fieldIndex}|]
            | MetadataTableKind.FileKind -> noImpl ()
            | MetadataTableKind.GenericParamKind ->
                genericParams <-
                    [|for _ in 1u .. rowCount do
                        let number = r.ReadUInt16 ()
                        let flags = r.ReadUInt16 ()
                        let ownerKind, ownerIndex = readCodedIndex TypeOrMethodDef
                        let name = readHeapString ()

                        printfn
                            "GenericParamKind: number=%i, flags=0x%X, owner=(%A, %i), name=\"%s\""
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
            | MetadataTableKind.GenericParamConstraintKind ->
                genericParamConstraints <-
                    [|for _ in 1u .. rowCount do
                        let ownerIndex = readTableIndex MetadataTableKind.GenericParamKind
                        let constraintKind, constraintIndex = readCodedIndex TypeDefOrRef

                        printfn
                            "GenericParamConstraintKind: owner=%i, constraint=(%A, %i)"
                            ownerIndex
                            constraintKind
                            constraintIndex

                        yield {
                            GenericParamConstraintRow.ownerIndex = ownerIndex
                            constraintKind = constraintKind
                            constraintIndex = constraintIndex}|]
            | MetadataTableKind.ImplMapKind ->
                implMaps <-
                    [|for _ in 1u .. rowCount do
                        let mappingFlags = r.ReadUInt16 ()
                        //it only ever indexes the MethodDef table, since Field export is not supported
                        let memberForwardedKind, memberForwardedIndex = readCodedIndex MemberForwarded
                        let importName = readHeapString ()
                        let importScopeIndex = readTableIndex MetadataTableKind.ModuleRefKind

                        printfn
                            "ImplMapKind: forwarded=(%A, %i), importName=\"%s\", importScopeIndex=%i"
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
            | MetadataTableKind.InterfaceImplKind ->
                interfaceImpls <-
                    [|for _ in 1u .. rowCount do
                        let classIndex = readTableIndex MetadataTableKind.TypeDefKind
                        let ifaceKind, ifaceIndex = readCodedIndex TypeDefOrRef

                        printfn "InterfaceImplKind: class=%i, interface=(%A, %i)" classIndex ifaceKind ifaceIndex

                        yield {
                            InterfaceImplRow.classIndex = classIndex
                            ifaceKind = ifaceKind
                            ifaceIndex = ifaceIndex}|]
            | MetadataTableKind.ManifestResourceKind ->
                manifestResources <-
                    [|for _ in 1u .. rowCount do
                        let offset = r.ReadUInt32 ()
                        let flags = r.ReadUInt32 ()
                        let name = readHeapString ()
                        let implKind, implIndex = readCodedIndex Implementation

                        printfn "ManifestResourceKind: name=\"%s\", impl=(%A, %i)" name implKind implIndex

                        yield {
                            ManifestResourceRow.offset = offset
                            flags = flags
                            name = name
                            implKind = implKind
                            implIndex = implIndex}|]
            | MetadataTableKind.MemberRefKind ->
                memberRefs <-
                    [|for _ in 1u .. rowCount do
                        let classKind, classIndex = readCodedIndex MemberRefParent
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()
                        
                        printfn "MemberRefKind: class=(%A, %i) name=\"%s\", sigIndex=%i" classKind classIndex name signatureIndex

                        yield {
                            MemberRefRow.classKind = classKind
                            classIndex = classIndex
                            name = name
                            signatureIndex = signatureIndex}|]
            | MetadataTableKind.MethodDefKind ->
                methodDefs <-
                    [|for _ in 1u .. rowCount do
                        let rva = r.ReadUInt32 ()
                        let implFlags = r.ReadUInt16 ()
                        let flags = r.ReadUInt16 ()
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()
                        let paramIndex = readTableIndex MetadataTableKind.ParamKind

                        printfn "MethodDefKind: name=\"%s\", sigIndex=%i, paramIndex=%i" name signatureIndex paramIndex

                        yield {
                            MethodDefRow.rva = rva
                            implFlags = implFlags
                            flags = flags
                            name = name
                            signatureIndex = signatureIndex
                            paramIndex = paramIndex}|]
            | MetadataTableKind.MethodImplKind ->
                methodImpls <-
                    [|for _ in 1u .. rowCount do
                        let classIndex = readTableIndex MetadataTableKind.TypeDefKind
                        let methodBodyKind, methodBodyIndex = readCodedIndex MethodDefOrRef
                        let methodDecKind, methodDecIndex = readCodedIndex MethodDefOrRef

                        printfn
                            "MethodImplKind: class=%i, body=(%A, %i), declaration=(%A, %i)"
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
            | MetadataTableKind.MethodSemanticsKind ->
                methodSemantics <-
                    [|for _ in 1u .. rowCount do
                        let semanticsFlags = r.ReadUInt16 ()
                        let methodIndex = readTableIndex MetadataTableKind.MethodDefKind
                        let assocKind, assocIndex = readCodedIndex HasSemantics

                        printfn
                            "MethodSemanticsKind: semantics=0x%X, methodIndex=%i, assoc=(%A, %i)"
                            semanticsFlags
                            methodIndex
                            assocKind
                            assocIndex

                        yield {
                            MethodSemanticsRow.semanticsFlags = semanticsFlags
                            methodIndex = methodIndex
                            assocKind = assocKind
                            assocIndex = assocIndex}|]
            | MetadataTableKind.MethodSpecKind ->
                methodSpecs <-
                    [|for _ in 1u .. rowCount do
                        let methodKind, methodIndex = readCodedIndex MethodDefOrRef
                        let instIndex = readBlobHeapIndex ()

                        printfn "MethodSpecKind: method=(%A, %i), instantiation=%i" methodKind methodIndex instIndex

                        yield {
                            MethodSpecRow.methodKind = methodKind
                            methodIndex = methodIndex
                            instIndex = instIndex}|]
            | MetadataTableKind.ModuleKind ->
                modules <-
                    [|for _ in 1u .. rowCount do
                        readShortEq r 0us "module generation"
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
            | MetadataTableKind.ModuleRefKind ->
                moduleRefs <-
                    [|for _ in 1u .. rowCount do
                        let name = readHeapString ()

                        printfn "ModuleRefKind: \"%s\"" name

                        yield {ModuleRefRow.name = name}|]
            | MetadataTableKind.NestedClassKind ->
                nestedClasses <-
                    [|for _ in 1u .. rowCount do
                        let nestedClassIndex = readTableIndex MetadataTableKind.TypeDefKind
                        let enclosingClassIndex = readTableIndex MetadataTableKind.TypeDefKind

                        printfn
                            "NestedClassKind: nestedClass=%i, enclosingClass=%i"
                            nestedClassIndex
                            enclosingClassIndex

                        yield {
                            NestedClassRow.nestedClassIndex = nestedClassIndex
                            enclosingClassIndex = enclosingClassIndex}|]
            | MetadataTableKind.ParamKind ->
                paramRows <-
                    [|for _ in 1u .. rowCount do
                        let flags = r.ReadUInt16 ()
                        let sequence = r.ReadUInt16 ()
                        let name = readHeapString ()
                        
                        printfn "ParamKind: name=\"%s\", seq=%i" name sequence

                        yield {
                            ParamRow.flags = flags
                            sequence = sequence
                            name = name}|]
            | MetadataTableKind.PropertyKind ->
                properties <-
                    [|for _ in 1u .. rowCount do
                        let flags = r.ReadUInt16 ()
                        let name = readHeapString ()
                        // The name of this column is misleading.  It does not index
                        // a TypeDef or TypeRef table. Instead it indexes the
                        // signature in the Blob heap of the Property
                        let typeIndex = readBlobHeapIndex ()

                        printfn "PropertyKind: name=\"%s\", type=%i" name typeIndex

                        yield {
                            PropertyRow.flags = flags
                            name = name
                            typeIndex = typeIndex}|]
            | MetadataTableKind.PropertyMapKind ->
                propertyMaps <-
                    [|for _ in 1u .. rowCount do
                        let parentIndex = readTableIndex MetadataTableKind.TypeDefKind
                        let propertyListIndex = readTableIndex MetadataTableKind.PropertyKind

                        printfn "PropertyMapKind: parent=%i, propertyList=%i" parentIndex propertyListIndex

                        yield {
                            PropertyMapRow.parentIndex = parentIndex
                            propertyListIndex = propertyListIndex}|]
            | MetadataTableKind.StandAloneSigKind ->
                standAloneSigs <-
                    [|for _ in 1u .. rowCount do
                        let signatureIndex = readBlobHeapIndex ()
                        printfn "StandAloneSigKind: sigIndex=%i" signatureIndex

                        yield {StandAloneSigRow.signatureIndex = signatureIndex}|]
            | MetadataTableKind.TypeDefKind ->
                typeDefs <-
                    [|for _ in 1u .. rowCount do
                        let flags = r.ReadUInt32 ()
                        let typeName = readHeapString ()
                        let typeNamespace = readHeapString ()
                        let extendsKind, extendsIndex = readCodedIndex TypeDefOrRef
                        let fieldsIndex = readTableIndex MetadataTableKind.FieldKind
                        let methodsIndex = readTableIndex MetadataTableKind.MethodDefKind

                        printfn "TypeDefKind: typeName=\"%s\", typeNamespace=\"%s\"" typeName typeNamespace

                        yield {
                            TypeDefRow.flags = flags
                            typeName = typeName
                            typeNamespace = typeNamespace
                            extendsKind = extendsKind
                            extendsIndex = extendsIndex
                            fieldsIndex = fieldsIndex
                            methodsIndex = methodsIndex}|]
            | MetadataTableKind.TypeRefKind ->
                typeRefs <-
                    [|for _ in 1u .. rowCount do
                        let resolutionScopeKind, resolutionScopeIndex = readCodedIndex ResolutionScope
                        let typeName = readHeapString ()
                        let typeNamespace = readHeapString ()

                        printfn
                            "TypeRefKind: resolutionScope=(%A, %i), typeName=\"%s\", typeNamespace=\"%s\""
                            resolutionScopeKind
                            resolutionScopeIndex
                            typeName
                            typeNamespace

                        yield {
                            TypeRefRow.resolutionScopeKind = resolutionScopeKind
                            resolutionScopeIndex = resolutionScopeIndex
                            typeName = typeName
                            typeNamespace = typeNamespace}|]
            | MetadataTableKind.TypeSpecKind ->
                typeSpecs <-
                    [|for _ in 1u .. rowCount do
                        let sigIndex = readBlobHeapIndex ()
                        printfn "TypeSpecKind: %i" sigIndex

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
            fieldLayouts = fieldLayouts
            fieldMarshals = fieldMarshals
            fieldRVAs = fieldRVAs
            eventMap = eventMap
            events = events
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
