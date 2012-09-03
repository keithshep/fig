module Fig.AssemblyParser

open Fig.IOUtil
open Fig.ParseCode

open System.IO
open System.Reflection.Emit

let rec splitAt i xs =
    if i = 0 then
        ([], xs)
    else
        match xs with
        | [] -> failwith "not enough elements for split"
        | x :: xt ->
            let splitFst, splitSnd = splitAt (i - 1) xt
            (x :: splitFst, splitSnd)

/// for keeping track of what types will be on the stack
/// See EMCA 335:
/// - Partition I 12.3.2.1: The Evaluation Stack
/// - Partition III 1.1: Data Types
/// - Partition III 1.5: Operant Type Table
type StackType =
    | Int32_ST
    | Int64_ST
    | NativeInt_ST
    | Float32_ST
    | Float64_ST
    | ObjectRef_ST
    | ManagedPointer_ST
    with
        interface StackTyped with
            member x.StackType = x
and StackTyped =
    abstract member StackType : StackType with get
let (|Int_ST|Float_ST|Managed_ST|) = function
    | Int32_ST | Int64_ST | NativeInt_ST ->
        Int_ST
    | Float32_ST | Float64_ST ->
        Float_ST
    | ObjectRef_ST | ManagedPointer_ST ->
        Managed_ST
let (|STyped|) (st : #StackTyped) = STyped st.StackType

/// See Partition VI C.2: CIL OpCode Descriptions (contains push/pop behaviors of each inst)
type InstPopKind =
    | Pop0 | Pop1 | Pop1Pop1 | PopI | PopIPop1
    | PopIPopI | PopIPopIPopI | PopI8Pop8 | PopIPopR4
    | PopIPopR8 | PopRef | PopRefPopI | PopRefPopIPopI
    | PopRefPopIPopI8 | PopRefPopIPopR4 | PopRefPopIPopR8
    | VarPop | PopAll

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

type [<RequireQualifiedAccess>] CodedIndexKind =
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
    parentIndex : int}

type ConstantRow = {
    typeVal : ElementType
    parentKind : MetadataTableKind
    parentIndex : int
    valueIndex : uint32}

type CustomAttributeRow = {
    parentKind : MetadataTableKind
    parentIndex : int
    // The column called Type is slightly misleading
    // it actually indexes a constructor method
    // the owner of that constructor method is
    //the Type of the Custom Attribute.
    typeKind : MetadataTableKind
    typeIndex : int
    valueIndex : uint32}

type DeclSecurityRow = {
    action : uint16
    parentKind : MetadataTableKind
    parentIndex : int
    permissionSetIndex : uint32}

type EventMapRow = {
    parentTypeDefIndex : int
    eventStartIndex : int}

type EventRow = {
    eventFlags : uint16
    name : string
    eventTypeKind : MetadataTableKind
    eventTypeIndex : int}

/// The rows in the ExportedType table are the result of the .class	extern directive
type ExportedTypeRow = {
    flags : uint32

    /// This column is used as a hint only. If the entry in the target TypeDef table
    /// matches the TypeName and TypeNamespace entries in this table, resolution has
    /// succeeded. But if there is a mismatch, the CLI shall fall back to a search
    /// of the target TypeDef table.
    /// Ignored and should be zero if Flags has IsTypeForwarder set.
    typeDefId : uint32
    typeName : string
    typeNamespace : string option
    implKind : MetadataTableKind
    implIndex : int}

type FieldRow = {
    fieldAttrFlags : uint16
    name : string
    signatureIndex : uint32}

type FieldLayoutRow = {
    offset : uint32
    fieldIndex : int}

type FieldMarshalRow = {
    parentKind : MetadataTableKind
    parentIndex : int
    nativeTypeIndex : uint32}

type FieldRVARow = {
    rva : uint32
    fieldIndex : int}

type GenericParamRow = {
    number : uint16
    flags : uint16
    ownerKind : MetadataTableKind
    ownerIndex : int
    name : string}

type GenericParamConstraintRow = {
    ownerIndex : int
    constraintKind : MetadataTableKind
    constraintIndex : int}

type ImplMapRow = {
    mappingFlags : uint16
    //it only ever indexes the MethodDef table, since Field export is not supported
    memberForwardedKind : MetadataTableKind
    memberForwardedIndex : int
    importName : string
    importScopeIndex : int}

type InterfaceImplRow = {
    classIndex : int
    ifaceKind : MetadataTableKind
    ifaceIndex : int}

type ManifestResourceRow = {
    offset : uint32
    flags : uint32
    name : string
    implKind : MetadataTableKind
    implIndex : int}

type MemberRefRow = {
    classKind : MetadataTableKind
    classIndex : int
    name : string
    signatureIndex : uint32}

type MethodDefRow = {
    rva : uint32
    implFlags : uint16
    flags : uint16
    name : string
    signatureIndex : uint32
    paramIndex : int}

type MethodImplRow = {
    classIndex : int
    methodBodyKind : MetadataTableKind
    methodBodyIndex : int
    methodDecKind : MetadataTableKind
    methodDecIndex : int}

type MethodSemanticsRow = {
    semanticsFlags : uint16
    methodIndex : int
    assocKind : MetadataTableKind
    assocIndex : int}

type MethodSpecRow = {
    methodKind : MetadataTableKind
    methodIndex : int
    instIndex : uint32}

type ModuleRow = {
    name : string
    mvidIndex : uint32
    encIDIndex : uint32
    encBaseIdIndex : uint32}

type ModuleRefRow = {
    name : string}

type NestedClassRow = {
    nestedClassIndex : int
    enclosingClassIndex : int}

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
    parentIndex : int
    propertyListIndex : int}

type StandAloneSigRow = {
    signatureIndex : uint32}

type TypeDefRow = {
    flags : uint32
    typeName : string
    typeNamespace : string option
    extendsKind : MetadataTableKind
    extendsIndex : int
    fieldsIndex : int
    methodsIndex : int}

type TypeRefRow = {
    resolutionScopeKind : MetadataTableKind
    resolutionScopeIndex : int
    typeName : string
    typeNamespace : string option}

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
    exportedTypes : ExportedTypeRow array
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

type IAssemblyResolution =
    abstract Mscorlib : Assembly with get
    abstract ResolveAssembly : AssemblyRef -> Assembly
    abstract RegisterAssembly : Assembly -> unit

and Assembly(r : PosStackBinaryReader, assemRes : IAssemblyResolution) as x =
    inherit AssemblyBase()
    
    // see EMCA-335 25.2.1
    let readMSDOSHeader () : uint32 =
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

    // specified in EMCA-335 25.2.2
    let peHeader : PEHeader =
        let peOffset = readMSDOSHeader()
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
                (*if imageSize % sectionAlignment <> 0u then
                    debugfn "image size expected to be a multiple of section alignment"*)
                let headerSize = r.ReadUInt32 ()
                (*if headerSize % fileAlignment <> 0u then
                    debugfn "header size expected to be a multiple of file alignment"*)
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
                //debugfn "importtbl rva %i 0x%X and size %i 0x%X" importTableRVA importTableRVA importTableSize importTableSize
                //readImportTables r |> ignore
                //debugfn "READ"
                //r.PopPos ()
                //debugfn "POPPED"
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
                //debugfn "CLI header: %i %i" cliHeaderRVA cliHeaderSize
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
    let readSectionHeader () =
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

    let sectionHeaders : list<SectionHeader> =
        [for _ in 1us .. peHeader.numSections -> readSectionHeader()]

    // From EMCA-335 25
    // The PE format frequently uses the term RVA (Relative Virtual Address). An RVA is the address of an item
    // once loaded into memory, with the base address of the image file subtracted from it (i.e., the offset from the
    // base address where the file is loaded). The RVA of an item will almost always differ from its position within
    // the file on disk. To compute the file position of an item with RVA r, search all the sections in the PE file to find
    // the section with RVA s, length l and file position p in which the RVA lies, ie s <= r < s+l. The file position of
    // the item is then given by p+(r-s).
    let rec rvaToDiskPosOpt (secHeaders : SectionHeader list) (r : uint32) : option<int64> =
        match secHeaders with
        | {virtSize = l; virtAddr = s; ptrToRawData = p} :: hdrTail ->
            if s <= r && r < s + l then
                let diskPos = p + (r - s)
                Some (int64 diskPos)
            else
                rvaToDiskPosOpt hdrTail r
        | [] ->
            None

    let rvaToDiskPos (r : uint32) : int64 =
        match rvaToDiskPosOpt sectionHeaders r with
        | Some x -> x
        | None -> failwithf "failed to locate RVA 0x%X" r

    // 25.3.3 CLI Header
    let cliHeader : CLIHeader =
        match peHeader.optHeader with
        | None -> failwith "can't read CLI with missing optional PE header"
        | Some {cliHeaderRVA = rvi} ->
            r.BaseStream.Seek (rvaToDiskPos rvi, SeekOrigin.Begin) |> ignore
            readIntEq r 72u "size in bytes"
            let majorRuntimeVersion = r.ReadUInt16 ()
            let minorRuntimeVersion = r.ReadUInt16 ()
            let metaDataRVA = r.ReadUInt32 ()
            let metaDataSize = r.ReadUInt32 ()
            let flags = r.ReadUInt32 ()
            let entryPointTok = r.ReadUInt32 ()
            //debugfn "entry point tok: %i" entryPointTok
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
    
    let rraToDiskPos rootRelAddr =
        rvaToDiskPos (cliHeader.metaDataRVA + rootRelAddr)

    let readStreamHeader () =
        let offset = r.ReadUInt32 ()
        let size = r.ReadUInt32 ()
        let name = readAlignedASCII r 4
        (offset, size, name)

    let streamHeaders : Map<string, uint32 * uint32> =
        r.BaseStream.Seek (rvaToDiskPos cliHeader.metaDataRVA, SeekOrigin.Begin) |> ignore
        readIntEq r 0x424A5342u "magic signature for physical metadata"
        r.BaseStream.Seek (4L, SeekOrigin.Current) |> ignore
        readIntEq r 0u "reserved"
        let versionStrLen = r.ReadUInt32 ()
        let tempPos = r.BaseStream.Position
        //debugfn "version string: \"%s\", alloc: %i" (readASCII r) versionStrLen
        r.BaseStream.Seek (tempPos + int64 versionStrLen, SeekOrigin.Begin) |> ignore
        readShortEq r 0us "meta data flags"
        let numStreams = r.ReadUInt16 ()
        //debugfn "num streams %i" numStreams
    
        Map.ofList
            [for _ in 1us .. numStreams do
                let offset, size, name = readStreamHeader()
                //debugfn "offset = %i, size = %i, name = \"%s\"" offset size name
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

    let readMaybeWideIndex isWide =
        if isWide then
            r.ReadUInt32 ()
        else
            r.ReadUInt16 () |> uint32

    // see 24.2.6
    let heapSizes =
        match streamHeaders.TryFind "#~" with
        | None -> failwith "failed to find the \"#~\" stream"
        | Some (tildeOffset, _tildeSize) ->
            r.BaseStream.Seek (rraToDiskPos tildeOffset, SeekOrigin.Begin) |> ignore
        
            readIntEq r 0u "meta tables header reserved field"
            readByteEq r 2uy "major version of table schemata"
            readByteEq r 0uy "minor version of table schemata"
            r.ReadByte ()

    let heapOffset (heapName : string) =
        match streamHeaders.TryFind heapName with
        | Some (offset, _) -> offset
        | None -> failwithf "failed to find %s heap" heapName

    // 24.2.3 #Strings heap
    let stringsHeapOffset = heapOffset "#Strings"

    // 24.2.4 #US and #Blob heaps
    // Strings in the #US (user string) heap are encoded using 16-bit Unicode
    // encodings. The count on each string is the number of bytes (not characters)
    // in the string. Furthermore, there is an additional terminal byte (so all
    // byte counts are odd, not even). This final byte holds the value 1 if and
    // only if any UTF16 character within the string has any bit set in its top
    // byte, or its low byte is any of the following: 0x01–0x08, 0x0E–0x1F, 0x27,
    // 0x2D, 0x7F. Otherwise, it holds 0. The 1 signifies Unicode characters that
    // require handling beyond that normally provided for 8-bit encoding sets.
    let usHeapOffset = heapOffset "#US"
    let blobHeapOffset = heapOffset "#Blob"

    // 24.2.5 #GUID heap
    let guidHeapOffset = heapOffset "#GUID"

    let metadataTables =

        let readStringHeapIndex () =
            let stringHeapIndicesWide = heapSizes &&& 0x01uy <> 0x00uy
            readMaybeWideIndex stringHeapIndicesWide

        let readHeapString () =
            let i = readStringHeapIndex ()
            let strAddr = rraToDiskPos stringsHeapOffset + int64 i
            r.PushPos strAddr
            let str = readUTF8 r
            r.PopPos ()
            str
        let readHeapStringOpt() =
            match readHeapString() with
            | "" -> None
            | s -> Some s

        let readGUIDHeapIndex () =
            let guidHeapIndicesWide = heapSizes &&& 0x02uy <> 0x00uy
            readMaybeWideIndex guidHeapIndicesWide

        let readBlobHeapIndex () =
            let blobHeapIndicesWide = heapSizes &&& 0x04uy <> 0x00uy
            readMaybeWideIndex blobHeapIndicesWide

        readByteEq r 1uy "meta tables header second reserved field"
        let validTables = r.ReadUInt64 ()
        assertTableBitsValid validTables
        let _sortedTables = r.ReadUInt64 ()

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
            let oneBasedIndex =
                if tableIndicesWide mt then
                    r.ReadUInt32 ()
                else
                    r.ReadUInt16 () |> uint32
            int oneBasedIndex - 1

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
            
            tableKind, int rowIndex - 1

        let mutable assemblies = ([||] : AssemblyRow array)
        let mutable assemblyRefs = ([||] : AssemblyRefRow array)
        let mutable classLayouts = ([||] : ClassLayoutRow array)
        let mutable constants = ([||] : ConstantRow array)
        let mutable customAttributes = ([||] : CustomAttributeRow array)
        let mutable declSecurities = ([||] : DeclSecurityRow array)
        let mutable eventMap = ([||] : EventMapRow array)
        let mutable events = ([||] : EventRow array)
        let mutable exportedTypes = ([||] : ExportedTypeRow array)
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
            //debugfn "MetadataTableKind=%A" kv.Key
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
                        
                        //debugfn "Assembly: name=\"%s\", culture=\"%s\"" name culture

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
                //debugfn "AssemblyOS: skipping %i rows..." rowCount
                let tableSize = 4L * 3L
                r.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyProcessorKind ->
                //debugfn "AssemblyProcessorKind: skipping %i rows..." rowCount
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
                        
                        //debugfn "AssemblyRefKind: name=\"%s\", culture=\"%s\"" name culture

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
                //debugfn "AssemblyRefOSKind: skipping %i rows..." rowCount
                let tableSize = 4L * 3L + tableIndexWidth MetadataTableKind.AssemblyRefKind
                r.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.AssemblyRefProcessorKind ->
                //debugfn "AssemblyRefProcessorKind: skipping %i rows..." rowCount
                let tableSize = 4L + tableIndexWidth MetadataTableKind.AssemblyRefKind
                r.BaseStream.Seek (tableSize * int64 rowCount, SeekOrigin.Current) |> ignore
            | MetadataTableKind.ClassLayoutKind ->
                classLayouts <-
                    [|for _ in 1u .. rowCount do
                        let packingSize = r.ReadUInt16 ()
                        let classSize = r.ReadUInt32 ()
                        let parentIndex = readTableIndex MetadataTableKind.TypeDefKind

                        //debugfn "ClassLayoutKind: packingSize=%i, classSize=%i, parent=%i" packingSize classSize parentIndex

                        yield {
                            ClassLayoutRow.packingSize = packingSize
                            classSize = classSize
                            parentIndex = parentIndex}|]
            | MetadataTableKind.ConstantKind ->
                constants <-
                    [|for _ in 1u .. rowCount do
                        let typeVal = r.ReadByte ()
                        readByteEq r 0x00uy "constant type padding"
                        let parentKind, parentIndex = readCodedIndex CodedIndexKind.HasConstant
                        let valueIndex = readBlobHeapIndex ()

                        //debugfn "ConstantKind: type=0x0x%X, parent=(%A, %i), value=%i" typeVal parentKind parentIndex valueIndex

                        yield {
                            ConstantRow.typeVal = enum<ElementType>(int typeVal)
                            parentKind = parentKind
                            parentIndex = parentIndex
                            valueIndex = valueIndex}|]
            | MetadataTableKind.CustomAttributeKind ->
                customAttributes <-
                    [|for _ in 1u .. rowCount do
                        let parentKind, parentIndex = readCodedIndex CodedIndexKind.HasCustomAttribute
                        // The column called Type is slightly misleading
                        // it actually indexes a constructor method
                        // the owner of that constructor method is
                        // the Type of the Custom Attribute.
                        let typeKind, typeIndex = readCodedIndex CodedIndexKind.CustomAttributeType
                        let valueIndex = readBlobHeapIndex ()

                        (*debugfn
                            "CustomAttributeKind: parent=(%A, %i), type=(%A, %i), valueIndex=%i"
                            parentKind
                            parentIndex
                            typeKind
                            typeIndex
                            valueIndex*)

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
                        let parentKind, parentIndex = readCodedIndex CodedIndexKind.HasDeclSecurity
                        let permissionSetIndex = readBlobHeapIndex ()

                        (*debugfn
                            "DeclSecurityKind: action=%i, parent=(%A, %i), permissionSet=%i"
                            action
                            parentKind
                            parentIndex
                            permissionSetIndex*)

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

                        (*debugfn
                            "EventMapKind: parent=%i, eventStart=%i"
                            parentTypeDefIndex
                            eventStartIndex*)

                        yield {
                            EventMapRow.parentTypeDefIndex = parentTypeDefIndex
                            eventStartIndex = eventStartIndex}|]
            | MetadataTableKind.EventKind ->
                events <-
                    [|for _ in 1u .. rowCount do
                        let eventFlags = r.ReadUInt16()
                        let name = readHeapString()
                        let eventTypeKind, eventTypeIndex = readCodedIndex CodedIndexKind.TypeDefOrRef

                        (*debugfn
                            "EventKind: flags=0x%X, name=%s, eventType=(%A, %i)"
                            eventFlags
                            name
                            eventTypeKind
                            eventTypeIndex*)

                        yield {
                            EventRow.eventFlags = eventFlags
                            name = name
                            eventTypeKind = eventTypeKind
                            eventTypeIndex = eventTypeIndex}|]
            | MetadataTableKind.ExportedTypeKind ->
                exportedTypes <- [|
                    for _ in 1u .. rowCount do
                        let flags = r.ReadUInt32()
                        let typeDefId = r.ReadUInt32()
                        let typeName = readHeapString()
                        let typeNamespace = readHeapStringOpt()
                        let implKind, implIndex = readCodedIndex CodedIndexKind.Implementation

                        (*debugfn
                            "ExportedTypeKind: flags=0x%X, typeDefId=%i, typeName=%s, typeNamespace=%A, impl=(%A, %i)"
                            flags
                            typeDefId
                            typeName
                            typeNamespace
                            implKind
                            implIndex*)

                        yield {
                            ExportedTypeRow.flags = flags
                            typeDefId = typeDefId
                            typeName = typeName
                            typeNamespace = typeNamespace
                            implKind = implKind
                            implIndex = implIndex
                        }
                |]
            | MetadataTableKind.FieldKind ->
                fields <-
                    [|for _ in 1u .. rowCount do
                        let fieldAttrFlags = r.ReadUInt16 ()
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()

                        //debugfn "FieldKind: flags=0x%X, name=\"%s\", sigindex=%i" fieldAttrFlags name signatureIndex

                        yield {
                            FieldRow.fieldAttrFlags = fieldAttrFlags
                            name = name
                            signatureIndex = signatureIndex}|]
            | MetadataTableKind.FieldLayoutKind ->
                fieldLayouts <-
                    [|for _ in 1u .. rowCount do
                        let offset = r.ReadUInt32()
                        let fieldIndex = readTableIndex MetadataTableKind.FieldKind

                        //debugfn "FieldLayout: offset=%i, fieldIndex=%i" offset fieldIndex

                        yield {
                            FieldLayoutRow.offset = offset
                            fieldIndex = fieldIndex}|]
            | MetadataTableKind.FieldMarshalKind ->
                fieldMarshals <-
                    [|for _ in 1u .. rowCount do
                        let parentKind, parentIndex = readCodedIndex CodedIndexKind.HasFieldMarshall
                        let nativeTypeIndex = readBlobHeapIndex ()

                        //debugfn "FieldMarshalKind: parent=(%A, %i), nativeType=%i" parentKind parentIndex nativeTypeIndex

                        yield {
                            FieldMarshalRow.parentKind = parentKind
                            parentIndex = parentIndex
                            nativeTypeIndex = nativeTypeIndex}|]
            | MetadataTableKind.FieldRVAKind ->
                fieldRVAs <-
                    [|for _ in 1u .. rowCount do
                        let rva = r.ReadUInt32 ()
                        let fieldIndex = readTableIndex MetadataTableKind.FieldKind

                        //debugfn "FieldRVAKind: RVA=%i, fieldIndex=%i" rva fieldIndex

                        yield {
                            FieldRVARow.rva = rva
                            fieldIndex = fieldIndex}|]
            | MetadataTableKind.FileKind -> noImpl ()
            | MetadataTableKind.GenericParamKind ->
                genericParams <-
                    [|for _ in 1u .. rowCount do
                        let number = r.ReadUInt16 ()
                        let flags = r.ReadUInt16 ()
                        let ownerKind, ownerIndex = readCodedIndex CodedIndexKind.TypeOrMethodDef
                        let name = readHeapString ()

                        (*debugfn
                            "GenericParamKind: number=%i, flags=0x%X, owner=(%A, %i), name=\"%s\""
                            number
                            flags
                            ownerKind
                            ownerIndex
                            name*)

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
                        let constraintKind, constraintIndex = readCodedIndex CodedIndexKind.TypeDefOrRef

                        (*debugfn
                            "GenericParamConstraintKind: owner=%i, constraint=(%A, %i)"
                            ownerIndex
                            constraintKind
                            constraintIndex*)

                        yield {
                            GenericParamConstraintRow.ownerIndex = ownerIndex
                            constraintKind = constraintKind
                            constraintIndex = constraintIndex}|]
            | MetadataTableKind.ImplMapKind ->
                implMaps <-
                    [|for _ in 1u .. rowCount do
                        let mappingFlags = r.ReadUInt16 ()
                        //it only ever indexes the MethodDef table, since Field export is not supported
                        let memberForwardedKind, memberForwardedIndex = readCodedIndex CodedIndexKind.MemberForwarded
                        let importName = readHeapString ()
                        let importScopeIndex = readTableIndex MetadataTableKind.ModuleRefKind

                        (*debugfn
                            "ImplMapKind: forwarded=(%A, %i), importName=\"%s\", importScopeIndex=%i"
                            memberForwardedKind
                            memberForwardedIndex
                            importName
                            importScopeIndex*)

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
                        let ifaceKind, ifaceIndex = readCodedIndex CodedIndexKind.TypeDefOrRef

                        //debugfn "InterfaceImplKind: class=%i, interface=(%A, %i)" classIndex ifaceKind ifaceIndex

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
                        let implKind, implIndex = readCodedIndex CodedIndexKind.Implementation

                        //debugfn "ManifestResourceKind: name=\"%s\", impl=(%A, %i)" name implKind implIndex

                        yield {
                            ManifestResourceRow.offset = offset
                            flags = flags
                            name = name
                            implKind = implKind
                            implIndex = implIndex}|]
            | MetadataTableKind.MemberRefKind ->
                memberRefs <-
                    [|for _ in 1u .. rowCount do
                        let classKind, classIndex = readCodedIndex CodedIndexKind.MemberRefParent
                        let name = readHeapString ()
                        let signatureIndex = readBlobHeapIndex ()
                        
                        //debugfn "MemberRefKind: class=(%A, %i) name=\"%s\", sigIndex=%i" classKind classIndex name signatureIndex

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

                        //debugfn "MethodDefKind: name=\"%s\", sigIndex=%i, paramIndex=%i" name signatureIndex paramIndex

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
                        let methodBodyKind, methodBodyIndex = readCodedIndex CodedIndexKind.MethodDefOrRef
                        let methodDecKind, methodDecIndex = readCodedIndex CodedIndexKind.MethodDefOrRef

                        (*debugfn
                            "MethodImplKind: class=%i, body=(%A, %i), declaration=(%A, %i)"
                            classIndex
                            methodBodyKind
                            methodBodyIndex
                            methodDecKind
                            methodDecIndex*)

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
                        let assocKind, assocIndex = readCodedIndex CodedIndexKind.HasSemantics

                        (*debugfn
                            "MethodSemanticsKind: semantics=0x%X, methodIndex=%i, assoc=(%A, %i)"
                            semanticsFlags
                            methodIndex
                            assocKind
                            assocIndex*)

                        yield {
                            MethodSemanticsRow.semanticsFlags = semanticsFlags
                            methodIndex = methodIndex
                            assocKind = assocKind
                            assocIndex = assocIndex}|]
            | MetadataTableKind.MethodSpecKind ->
                methodSpecs <-
                    [|for _ in 1u .. rowCount do
                        let methodKind, methodIndex = readCodedIndex CodedIndexKind.MethodDefOrRef
                        let instIndex = readBlobHeapIndex ()

                        //debugfn "MethodSpecKind: method=(%A, %i), instantiation=%i" methodKind methodIndex instIndex

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
                        
                        //debugfn "module name=\"%s\"" name

                        yield {
                            ModuleRow.name = name
                            mvidIndex = mvidIndex
                            encIDIndex = encIDIndex
                            encBaseIdIndex = encBaseIdIndex}|]
            | MetadataTableKind.ModuleRefKind ->
                moduleRefs <-
                    [|for _ in 1u .. rowCount do
                        let name = readHeapString ()

                        //debugfn "ModuleRefKind: \"%s\"" name

                        yield {ModuleRefRow.name = name}|]
            | MetadataTableKind.NestedClassKind ->
                nestedClasses <-
                    [|for _ in 1u .. rowCount do
                        let nestedClassIndex = readTableIndex MetadataTableKind.TypeDefKind
                        let enclosingClassIndex = readTableIndex MetadataTableKind.TypeDefKind

                        (*debugfn
                            "NestedClassKind: nestedClass=%i, enclosingClass=%i"
                            nestedClassIndex
                            enclosingClassIndex*)

                        yield {
                            NestedClassRow.nestedClassIndex = nestedClassIndex
                            enclosingClassIndex = enclosingClassIndex}|]
            | MetadataTableKind.ParamKind ->
                paramRows <-
                    [|for _ in 1u .. rowCount do
                        let flags = r.ReadUInt16 ()
                        let sequence = r.ReadUInt16 ()
                        let name = readHeapString ()
                        
                        //debugfn "ParamKind: name=\"%s\", seq=%i" name sequence

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

                        //debugfn "PropertyKind: name=\"%s\", type=%i" name typeIndex

                        yield {
                            PropertyRow.flags = flags
                            name = name
                            typeIndex = typeIndex}|]
            | MetadataTableKind.PropertyMapKind ->
                propertyMaps <-
                    [|for _ in 1u .. rowCount do
                        let parentIndex = readTableIndex MetadataTableKind.TypeDefKind
                        let propertyListIndex = readTableIndex MetadataTableKind.PropertyKind

                        //debugfn "PropertyMapKind: parent=%i, propertyList=%i" parentIndex propertyListIndex

                        yield {
                            PropertyMapRow.parentIndex = parentIndex
                            propertyListIndex = propertyListIndex}|]
            | MetadataTableKind.StandAloneSigKind ->
                standAloneSigs <-
                    [|for _ in 1u .. rowCount do
                        let signatureIndex = readBlobHeapIndex ()
                        //debugfn "StandAloneSigKind: sigIndex=%i" signatureIndex

                        yield {StandAloneSigRow.signatureIndex = signatureIndex}|]
            | MetadataTableKind.TypeDefKind ->
                typeDefs <-
                    [|for _ in 1u .. rowCount do
                        let flags = r.ReadUInt32 ()
                        let typeName = readHeapString ()
                        let typeNamespace = readHeapStringOpt()
                        let extendsKind, extendsIndex = readCodedIndex CodedIndexKind.TypeDefOrRef
                        let fieldsIndex = readTableIndex MetadataTableKind.FieldKind
                        let methodsIndex = readTableIndex MetadataTableKind.MethodDefKind

                        //debugfn "TypeDefKind: typeName=\"%s\", typeNamespace=\"%A\"" typeName typeNamespace

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
                        let resolutionScopeKind, resolutionScopeIndex = readCodedIndex CodedIndexKind.ResolutionScope
                        let typeName = readHeapString ()
                        let typeNamespace = readHeapStringOpt()

                        (*debugfn
                            "TypeRefKind: resolutionScope=(%A, %i), typeName=\"%s\", typeNamespace=\"%A\""
                            resolutionScopeKind
                            resolutionScopeIndex
                            typeName
                            typeNamespace*)

                        yield {
                            TypeRefRow.resolutionScopeKind = resolutionScopeKind
                            resolutionScopeIndex = resolutionScopeIndex
                            typeName = typeName
                            typeNamespace = typeNamespace}|]
            | MetadataTableKind.TypeSpecKind ->
                typeSpecs <-
                    [|for _ in 1u .. rowCount do
                        let sigIndex = readBlobHeapIndex ()
                        //debugfn "TypeSpecKind: %i" sigIndex

                        yield {TypeSpecRow.sigIndex = sigIndex}|]
            | _ -> noImpl ()

        {
            MetadataTables.assemblies = assemblies
            assemblyRefs = assemblyRefs
            classLayouts = classLayouts
            constants = constants
            customAttributes = customAttributes
            declSecurities = declSecurities
            exportedTypes = exportedTypes
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

    do
        // TODO think about if it's really smart to register self in constructor
        assemRes.RegisterAssembly x

    member x.SectionHeaders = sectionHeaders
    member x.MetadataTables = metadataTables
    member x.AssemblyRow =
        match x.MetadataTables.assemblies with
        | [|assemRow|] -> assemRow
        | _ -> failwith "Expected a single assembly"

    member x.RVAToDiskPos (rva : uint32) : int64 = rvaToDiskPos rva
    member x.RRAToDiskPos (rra : uint32) : int64 = rraToDiskPos rra
    member x.SeekToBlobIndex (blobIndex : uint32) =
        let diskPos = rraToDiskPos blobHeapOffset + int64 blobIndex
        r.BaseStream.Seek (diskPos, SeekOrigin.Begin) |> ignore
    member x.ReadBlobAtIndex (blobIndex : uint32) =
        x.SeekToBlobIndex blobIndex
        let numBytes = readCompressedUnsignedInt r.ReadByte
        r.ReadBytes(int numBytes)
    member x.SeekToUSIndex (usIndex : uint32) =
        let diskPos = rraToDiskPos usHeapOffset + int64 usIndex
        r.BaseStream.Seek (diskPos, SeekOrigin.Begin) |> ignore
    member x.ReadUSAtIndex (usIndex : uint32) =
        x.SeekToUSIndex usIndex
        let numBytes = readCompressedUnsignedInt r.ReadByte
        let bytes = r.ReadBytes(int numBytes)
        System.Text.Encoding.Unicode.GetString bytes

    member x.AssemblyRefs = [|
        for i in 0 .. x.MetadataTables.assemblyRefs.Length - 1 ->
            new AssemblyRef(x, i)
    |]

    member x.Modules = [|
        for i in 0 .. x.MetadataTables.modules.Length - 1 ->
            new Module(x, i)
    |]

    member x.TypeDefNamed (tyNamespace : string option) (tyName : string) : TypeDef option =
        let rec go i =
            if i < metadataTables.typeDefs.Length then
                let currTyDef = metadataTables.typeDefs.[i]
                if currTyDef.typeNamespace = tyNamespace && currTyDef.typeName = tyName then
                    Some (new TypeDef(x, i))
                else
                    go (i + 1)
            else
                None
        go 0
    override x.Name = x.AssemblyRow.name
    override x.Culture = x.AssemblyRow.culture

    override x.MajorVersion = x.AssemblyRow.majorVersion
    override x.MinorVersion = x.AssemblyRow.minorVersion
    override x.RevisionNumber = x.AssemblyRow.revisionNumber
    override x.BuildNumber = x.AssemblyRow.buildNumber

    override x.AssemblyFlags = x.AssemblyRow.flags

    member x.AssemblyResolution = assemRes

    member x.Reader = r

    member x.EntryPoint : MethodDef option =
        // TODO this can be a methoddef **OR** a file
        // Section 25.3.3 Token for the MethodDef or File of the entry point for the image
        match toMetadataToken cliHeader.entryPointTok with
        | _, -1 ->
            None
        | Some MetadataTableKind.MethodDefKind, row ->
            Some (new MethodDef(x, row))
        | tok ->
            failwithf "implement entry point for %A" tok

and AssemblyRef(assem : Assembly, rowIndex : int) =
    inherit AssemblyBase()
    let mt = assem.MetadataTables
    let assemRefRow = mt.assemblyRefs.[rowIndex]

    let isFlagSet mask = assemRefRow.flags &&& mask <> 0u

    override x.Name = assemRefRow.name
    override x.Culture = assemRefRow.culture
    member x.HashValueIndex =
        // TODO give actual hash value
        assemRefRow.hashValueIndex

    override x.MajorVersion = assemRefRow.majorVersion
    override x.MinorVersion = assemRefRow.minorVersion
    override x.RevisionNumber = assemRefRow.revisionNumber
    override x.BuildNumber = assemRefRow.buildNumber

    override x.AssemblyFlags = assemRefRow.flags

    member x.IsPublicKeySet = isFlagSet 0x0001u

    member x.PublicKeyOrToken : byte array option =
        
        // TODO how can I interpret null below? 0 index is what I'm assuming for now...
        // PublicKeyOrToken can be null, or non-null (note that the Flags.PublicKey bit
        // specifies whether the 'blob' is a full public key, or the short hashed token
        match assemRefRow.publicKeyOrTokenIndex with
        | 0u -> None
        | i ->
            // see 6.2.1.3 Originator’s public key
            Some (assem.ReadBlobAtIndex i)

and [<AbstractClass>] AssemblyBase() =
    abstract Name : string with get
    abstract Culture : string with get

    abstract MajorVersion : uint16 with get
    abstract MinorVersion : uint16 with get
    abstract RevisionNumber : uint16 with get
    abstract BuildNumber : uint16 with get
    member x.Version =
        string x.MajorVersion + "." +
        string x.MinorVersion + "." +
        string x.RevisionNumber + "." +
        string x.BuildNumber

    abstract AssemblyFlags : uint32 with get

    override x.GetHashCode() : int =
        int x.MajorVersion
        ^^^ (int x.MinorVersion <<< 8)
        ^^^ (int x.RevisionNumber <<< 16)
        ^^^ (int <| rotL (uint32 x.BuildNumber) 24)
    override x.Equals otherObj : bool =
        match otherObj with
        | :? AssemblyBase as assem2 ->
            x.GetType() = assem2.GetType() && AssemblyBase.SameAssemblies x assem2
        | _ ->
            false

    static member SameAssemblies (assem1:AssemblyBase) (assem2:AssemblyBase) : bool =
        // TODO create a robust impl
        assem1.Name = assem2.Name
        && assem1.MajorVersion = assem2.MajorVersion
        && assem1.MinorVersion = assem2.MinorVersion
        && assem1.RevisionNumber = assem2.RevisionNumber
        && assem1.BuildNumber = assem2.BuildNumber

and Module(assem : Assembly, rowIndex : int) =
    let mt = assem.MetadataTables
    let moduleRow = mt.modules.[rowIndex]

    member x.TypeDefs =
        // TODO and how does this work with
        let allNestedIndexes =
            seq {for ncRow in mt.nestedClasses -> ncRow.nestedClassIndex}
            |> Set.ofSeq

        seq {
            for i = 0 to mt.typeDefs.Length - 1 do
                if not <| allNestedIndexes.Contains i then
                    yield new TypeDef(assem, i)
        }

    member x.Name = moduleRow.name

    member x.Assembly = assem

and ModuleRef(assem:Assembly, rowIndex:int) =
    let moduleRefRow = assem.MetadataTables.moduleRefs.[rowIndex]

    member x.Name = moduleRefRow.name

and [<AbstractClass>] FieldDefOrRef() =
    abstract Name : string with get
    abstract Resolve : unit -> FieldDef
    abstract Signature : FieldSig with get
    abstract CilId : assemCtxt:AssemblyBase -> string

    static member FromKindAndIndex (assem : Assembly) (mt : MetadataTableKind) (rowIndex : int) : FieldDefOrRef =
        match mt with
        | MetadataTableKind.FieldKind -> upcast new FieldDef(assem, rowIndex)
        | MetadataTableKind.MemberRefKind -> upcast new FieldRef(assem, rowIndex)
        | _ -> failwithf "cannot create a FieldDefOrRef from a %A" mt

    static member FromMetadataToken (assem : Assembly) (mt : MetadataToken) : FieldDefOrRef =
        match mt with
        | Some tableKind, i -> FieldDefOrRef.FromKindAndIndex assem tableKind i
        | None, _ -> failwith "failed to convert token into a field"

and FieldRef(assem : Assembly, rowIndex : int) =
    inherit FieldDefOrRef()

    let mt = assem.MetadataTables
    let frRow = mt.memberRefs.[rowIndex]

    override x.Name = frRow.name
    override x.Resolve() =
        let matchingFieldIn (ty : TypeDefOrRef) =
            let ty = ty.Resolve()
            match Array.filter (fun (field : FieldDef) -> field.Name = x.Name) ty.Fields with
            | [|matchingField|] -> matchingField
            | matches -> failwithf "expected a single field match for %s but got %i" x.Name matches.Length

        match frRow.classKind with
        | MetadataTableKind.MethodDefKind -> failwithf "TODO implement %A for field ref" frRow.classKind
        | MetadataTableKind.ModuleRefKind -> failwithf "TODO implement %A for field ref" frRow.classKind
        | MetadataTableKind.TypeDefKind -> failwithf "TODO implement %A for field ref" frRow.classKind
        | MetadataTableKind.TypeRefKind -> matchingFieldIn <| new TypeRef(assem, frRow.classIndex)
        | MetadataTableKind.TypeSpecKind ->
            let tySpec = new TypeSpec(assem, frRow.classIndex)
            match tySpec.TypeSpecBlob with
            | TypeSpecBlob.GenericInst genTyInst ->
                match genTyInst.genericType with
                | :? TypeDefOrRef as ty -> matchingFieldIn ty
                | ty -> failwithf "TODO sorry I don't do %A yet" ty
            | _ ->
                failwithf "TODO implement %A (%A) for field ref" frRow.classKind tySpec.TypeSpecBlob
        | kind -> failwithf "invalid class kind for field ref: %A" kind
    override x.Signature =
        let blob = ref(assem.ReadBlobAtIndex frRow.signatureIndex |> List.ofArray)
        FieldSig.FromBlob assem blob
    override x.CilId(assemCtxt:AssemblyBase) = x.Resolve().CilId(assemCtxt)

and FieldDef(assem : Assembly, rowIndex : int) =
    inherit FieldDefOrRef()

    let mt = assem.MetadataTables
    let fRow = mt.fields.[rowIndex]
    let isFlagSet mask = fRow.fieldAttrFlags &&& mask <> 0us

    member private x.RowIndex = rowIndex
    member private x.Assembly = assem

    override x.Name = fRow.name
    override x.Resolve() = x
    override x.Signature =
        let blob = ref(assem.ReadBlobAtIndex fRow.signatureIndex |> List.ofArray)
        FieldSig.FromBlob assem blob
    override x.CilId(assemCtxt:AssemblyBase) =
        let mySig = x.Signature
        spaceSepStrs [|
            for cm in mySig.customMods do
                yield cm.CilId(assemCtxt)
            yield mySig.fType.CilId(assemCtxt)
            yield x.FullName
        |]
    override x.ToString() = "FieldDef(" + x.CilId assem + ")"

    override x.GetHashCode() = rowIndex ^^^ assem.GetHashCode()
    override x.Equals otherObj =
        match otherObj with
        | :? FieldDef as otherField ->
            rowIndex = otherField.RowIndex && assem = otherField.Assembly
        | _ ->
            false

    member x.DeclaringType : TypeDef =
        let tdRows = mt.typeDefs
        let rec findDecTy (currIndex : int) =
            let foundType =
                currIndex = tdRows.Length - 1
                || rowIndex < tdRows.[currIndex + 1].fieldsIndex
            if foundType then
                new TypeDef(assem, currIndex)
            else
                findDecTy (currIndex + 1)
        findDecTy 0
    
    member x.FullName = x.DeclaringType.FullName + "::" + x.Name

    member x.MemberAccess = MemberAccess.FromUShort fRow.fieldAttrFlags

    member x.IsStatic           = isFlagSet 0x0010us
    member x.IsInitOnly         = isFlagSet 0x0020us
    member x.IsLiteral          = isFlagSet 0x0040us
    member x.NotSerialized      = isFlagSet 0x0080us
    member x.SpecialName        = isFlagSet 0x0200us
    member x.RTSpecialName      = isFlagSet 0x0400us
    member x.HasFieldMarshal    = isFlagSet 0x1000us
    member x.HasDefault         = isFlagSet 0x8000us

    member x.ConstantValue : Constant option =
        let consts = mt.constants
        let rec getConst(i : int) =
            if i < consts.Length then
                let currConst = consts.[i]
                match currConst.parentKind with
                | MetadataTableKind.FieldKind when currConst.parentIndex = rowIndex ->
                    Some(new Constant(assem, i))
                | _ ->
                    getConst(i + 1)
            else
                None

        getConst 0

    member x.Offset : uint32 option =
        let layouts = mt.fieldLayouts
        let rec getOffset(i : int) =
            if i < layouts.Length then
                if layouts.[i].fieldIndex = rowIndex then
                    Some layouts.[i].offset
                else
                    getOffset(i + 1)
            else
                None

        getOffset 0

    member x.FieldRVA =
        if isFlagSet 0x0100us then
            let rvas = mt.fieldRVAs
            let rec getRVA (i : int) =
                if rvas.[i].fieldIndex = rowIndex then
                    rvas.[i].rva
                else getRVA (i + 1)
            Some (getRVA 0)
        else
            None

    member x.Data : byte array option =
        match x.FieldRVA with
        | None -> None
        | Some rva ->
            let pos = assem.RVAToDiskPos rva
            match x.Signature.fType.SizeBytes with
            | None -> failwithf "failed to calculate size for %s" (x.Signature.fType.CilId assem)
            | Some size ->
                let r = assem.Reader
                r.BaseStream.Seek(pos, SeekOrigin.Begin) |> ignore
                Some (r.ReadBytes size)

and Constant(assem:Assembly, rowIndex:int) =
    let mt = assem.MetadataTables
    let constRow = mt.constants.[rowIndex]

    member x.Type = constRow.typeVal

    member x.Value = assem.ReadBlobAtIndex constRow.valueIndex

and [<AbstractClass>] TypeDefRefOrSpec() =
    abstract CilId : typeKindReq:bool * assemCtxt:AssemblyBase -> string
    abstract SizeBytes : int option with get
    abstract AsIntermediateType : unit -> StackType
    abstract AsTypeBlob : (*bool*) unit -> TypeBlob option

    static member FromKindAndIndex (assem : Assembly) (mt : MetadataTableKind) (rowIndex : int) : TypeDefRefOrSpec =
        match mt with
        | MetadataTableKind.TypeDefKind -> upcast new TypeDef(assem, rowIndex)
        | MetadataTableKind.TypeRefKind -> upcast new TypeRef(assem, rowIndex)
        | MetadataTableKind.TypeSpecKind -> upcast new TypeSpec(assem, rowIndex)
        | _ -> failwithf "cannot create a TypeDefOrRef from a %A" mt

    static member FromKindAndIndexOpt (assem : Assembly) (mt : MetadataTableKind) (rowIndex : int) : TypeDefRefOrSpec option =
        // TODO assert that object class gives None for Inherits
        if rowIndex = -1 then
            None
        else
            Some(TypeDefRefOrSpec.FromKindAndIndex assem mt rowIndex)

    static member FromMetadataToken (assem : Assembly) (mt : MetadataToken) : TypeDefRefOrSpec =
        match mt with
        | Some tableKind, i -> TypeDefRefOrSpec.FromKindAndIndex assem tableKind i
        | None, _ -> failwith "failed to convert token into a type"

    static member FromBlob (assem : Assembly) (blob : byte list ref) : TypeDefRefOrSpec =
        // see partition II 23.2.8 TypeDefOrRefOrSpecEncoded
        let encoding = readCompressedUnsignedInt (makeReadByteFun blob)
        let rowIndex = int (encoding >>> 2) - 1
        let tableKind =
            match encoding &&& 0b11u with
            | 0u -> MetadataTableKind.TypeDefKind
            | 1u -> MetadataTableKind.TypeRefKind
            | 2u -> MetadataTableKind.TypeSpecKind
            | _ -> failwith "this is impossible"
        TypeDefRefOrSpec.FromKindAndIndex assem tableKind rowIndex

    static member SameType (ty1 : TypeDefRefOrSpec) (ty2 : TypeDefRefOrSpec) =
        match ty1, ty2 with
        | (:? TypeDefOrRef as ty1), (:? TypeDefOrRef as ty2) ->
            ty1.Namespace = ty2.Namespace && ty1.Name = ty2.Name
        | _ ->
            // TODO what should we really be doing for typespec here?
            false

and [<AbstractClass>] TypeDefOrRef() =
    inherit TypeDefRefOrSpec()
    abstract Resolve : unit -> TypeDef
    abstract Namespace : string option
    abstract Name : string

    member x.FullName =
        match x.Namespace with
        | None -> x.Name
        | Some ns -> ns + "." + x.Name

and TypeSpec(assem : Assembly, rowIndex : int) =
    inherit TypeDefRefOrSpec()

    let mt = assem.MetadataTables
    let typeSpecRow = mt.typeSpecs.[rowIndex]

    let typeSpecBlob =
        let blob = ref(assem.ReadBlobAtIndex typeSpecRow.sigIndex |> List.ofArray)
        TypeSpecBlob.FromBlob assem blob

    member x.TypeSpecBlob = typeSpecBlob

    override x.CilId(typeKindReq:bool, assemCtxt:AssemblyBase) = "TODO impl CilId for typespec"

    override x.SizeBytes = None
    (*
    override x.Namespace =
        match typeSpecBlob with
        | TypeSpecBlob.Array _
        | TypeSpecBlob.FnPtr _
        | TypeSpecBlob.Ptr _
        | TypeSpecBlob.SzArray _ ->
            Some "System"
        | TypeSpecBlob.GenericInst _ ->
            Some "TODO_generic_inst_namespace_here"
        | TypeSpecBlob.MVar _ | TypeSpecBlob.Var _ ->
            None
    override x.Name =
        match typeSpecBlob with
        | TypeSpecBlob.Array _
        | TypeSpecBlob.SzArray _ ->
            "Array"
        | TypeSpecBlob.FnPtr _
        | TypeSpecBlob.Ptr _ ->
            failwith "what the heck to i do with these pointers"
        | TypeSpecBlob.GenericInst _ ->
            "TODO_generic_inst_name_here"
        | TypeSpecBlob.MVar _ | TypeSpecBlob.Var _ ->
            "TODO deal with var types"
    *)

    override x.AsIntermediateType() : StackType = typeSpecBlob.AsTypeBlob().AsIntermediateType()
    override x.AsTypeBlob() : TypeBlob option = Some (typeSpecBlob.AsTypeBlob())

and TypeRef(assem : Assembly, rowIndex : int) =
    inherit TypeDefOrRef()

    let mt = assem.MetadataTables
    let typeRefRow = mt.typeRefs.[rowIndex]

    override x.Namespace = typeRefRow.typeNamespace
    override x.Name = typeRefRow.typeName
    override x.Resolve() =
        let assemRes = assem.AssemblyResolution
        match typeRefRow.resolutionScopeKind with
        | MetadataTableKind.ModuleKind ->
            failwith "impl ref"
        | MetadataTableKind.ModuleRefKind ->
            failwith "impl mod ref"
        | MetadataTableKind.AssemblyRefKind ->
            let assemRef = new AssemblyRef(assem, typeRefRow.resolutionScopeIndex)
            let resolvedAssem = assemRes.ResolveAssembly assemRef
            match resolvedAssem.TypeDefNamed typeRefRow.typeNamespace typeRefRow.typeName with
            | Some tyDef -> tyDef
            | None -> failwithf "failed to find type (%A).%s" typeRefRow.typeNamespace typeRefRow.typeName
        | MetadataTableKind.TypeRefKind ->
            failwith "impl type ref"
        | rsk ->
            failwith "unexpected resolution scope table kind %A" rsk

    override x.CilId(typeKindReq:bool, assemCtxt:AssemblyBase) =
        x.Resolve().CilId(typeKindReq, assemCtxt)
    override x.ToString() = "TypeRef(" + x.CilId(false, assem) + ")"
    override x.SizeBytes = x.Resolve().SizeBytes
    override x.AsIntermediateType() = x.Resolve().AsIntermediateType()
    override x.AsTypeBlob ( (*unbox:bool*) ) : TypeBlob option = x.Resolve().AsTypeBlob( (*unbox*) )

and [<RequireQualifiedAccess>] TypeVisibilityAttr =
    | NotPublic
    | Public
    | NestedPublic
    | NestedPrivate
    | NestedFamily
    | NestedAssembly
    | NestedFamANDAssem
    | NestedFamORAssem

and [<RequireQualifiedAccess>] ClassLayoutAttr = Auto | Sequential | Explicit
and [<RequireQualifiedAccess>] StringFmtAttr = Ansi | Unicode | Auto | Custom
and [<RequireQualifiedAccess>] TypeKind = Interface | Class | Valuetype | Enum | Delegate

and TypeDef(assem : Assembly, rowIndex : int) =
    inherit TypeDefOrRef()

    let mt = assem.MetadataTables
    let typeDefRow = mt.typeDefs.[rowIndex]
    
    let isFlagSet mask = typeDefRow.flags &&& mask <> 0u

    override x.Namespace = typeDefRow.typeNamespace
    override x.Name = typeDefRow.typeName
    override x.Resolve() = x

    override x.CilId(typeKindReq:bool, assemCtxt:AssemblyBase) =
        let fullName() =
            if AssemblyBase.SameAssemblies assem assemCtxt then
                x.FullName
            else
                "[" + assem.Name + "]" + x.FullName
        if typeKindReq then
            let tkStr =
                match x.TypeKind with
                | TypeKind.Class | TypeKind.Interface | TypeKind.Delegate -> "class"
                | TypeKind.Valuetype -> "valuetype"
                | tk -> failwithf "TODO woah don't know how to deal with %A" tk
            tkStr + " " + fullName()
        else
            fullName()
    override x.ToString() = "TypeDef(" + x.CilId(false, assem) + ")"

    override x.GetHashCode() = rowIndex ^^^ assem.GetHashCode()
    override x.Equals otherObj =
        match otherObj with
        | :? TypeDef as otherTy ->
            rowIndex = otherTy.RowIndex && assem = otherTy.Assembly
        | _ ->
            false

    member x.Assembly = assem
    member x.RowIndex = rowIndex
    member x.Module = assem.Modules.[0] // TODO what is the right way to do this

    member x.TypeVisibilityAttr =
        let visibilityMask = 0x00000007u
        match typeDefRow.flags &&& visibilityMask with
        | 0x00000000u -> TypeVisibilityAttr.NotPublic
        | 0x00000001u -> TypeVisibilityAttr.Public
        | 0x00000002u -> TypeVisibilityAttr.NestedPublic
        | 0x00000003u -> TypeVisibilityAttr.NestedPrivate
        | 0x00000004u -> TypeVisibilityAttr.NestedFamily
        | 0x00000005u -> TypeVisibilityAttr.NestedAssembly
        | 0x00000006u -> TypeVisibilityAttr.NestedFamANDAssem
        | 0x00000007u -> TypeVisibilityAttr.NestedFamORAssem
        | v -> failwithf "unexpected type visibility flag: %X" v

    member x.ClassLayoutAttr =
        let layoutMask = 0x00000018u
        match typeDefRow.flags &&& layoutMask with
        | 0x00000000u -> ClassLayoutAttr.Auto
        | 0x00000008u -> ClassLayoutAttr.Sequential
        | 0x00000010u -> ClassLayoutAttr.Explicit
        | v -> failwithf "unexpected class layout flag: %X" v

    member x.ClassLayout : ClassLayoutRow option =
        Array.tryFind (fun cl -> cl.parentIndex = rowIndex) mt.classLayouts

    member x.IsInterface    = isFlagSet 0x00000020u
    member x.IsAbstract     = isFlagSet 0x00000080u
    member x.IsSealed       = isFlagSet 0x00000100u
    member x.IsSpecialName  = isFlagSet 0x00000400u
    member x.IsImported     = isFlagSet 0x00001000u
    member x.IsSerializable = isFlagSet 0x00002000u

    member x.StringFormattingAttr =
        match typeDefRow.flags &&& 0x00030000u with
        | 0x00000000u -> StringFmtAttr.Ansi
        | 0x00010000u -> StringFmtAttr.Unicode
        | 0x00020000u -> StringFmtAttr.Auto
        | 0x00030000u -> StringFmtAttr.Custom
        | sf -> failwithf "unexpected string format attribute: %X" sf

    member x.BeforeFieldInit    = isFlagSet 0x00100000u
    member x.RTSpecialName      = isFlagSet 0x00000800u
    member x.HasSecurity        = isFlagSet 0x00040000u
    member x.IsTypeForwarder    = isFlagSet 0x00200000u

    member x.GenericParams = seq {
        for i in 0 .. mt.genericParams.Length - 1 do
            let gpRow = mt.genericParams.[i]
            let isMatch =
                gpRow.ownerKind = MetadataTableKind.TypeDefKind
                &&
                gpRow.ownerIndex = rowIndex
            if isMatch then
                yield new GenericParam(assem, i)
    }

    member x.Extends : TypeDefRefOrSpec option =
        TypeDefRefOrSpec.FromKindAndIndexOpt assem typeDefRow.extendsKind typeDefRow.extendsIndex

    member x.InheritanceChain : TypeDefRefOrSpec list =
        let rec go (tyOpt : TypeDefRefOrSpec option) : TypeDefRefOrSpec list =
            match tyOpt with
            | None -> []
            | Some (:? TypeDefOrRef as ty) ->
                upcast ty :: go (ty.Resolve().Extends)
            | _ ->
                failwith "TypeDef.InheritanceChain: not yet implemented for typespecs"

        go x.Extends

    member x.Implements = [|
        for iImpl in mt.interfaceImpls do
            if iImpl.classIndex = rowIndex then
                yield TypeDefRefOrSpec.FromKindAndIndex assem iImpl.ifaceKind iImpl.ifaceIndex
    |]

    member x.NestedTypes = [|
        for ncRow in mt.nestedClasses do
            if ncRow.enclosingClassIndex = rowIndex then
                yield new TypeDef(assem, ncRow.nestedClassIndex)
    |]

    member x.Fields : FieldDef array =
        let lastFieldIndex =
            let isLastTypeDef = rowIndex = mt.typeDefs.Length - 1
            if isLastTypeDef then
                mt.fields.Length - 1
            else
                mt.typeDefs.[rowIndex + 1].fieldsIndex - 1

        [|for i in typeDefRow.fieldsIndex .. lastFieldIndex -> new FieldDef(assem, i)|]

    member x.InstanceFields = Array.filter (fun (f : FieldDef) -> not f.IsStatic) x.Fields
    member x.InheritedInstanceFields = [|
        for ty in List.rev x.InheritanceChain do
            match ty with
            | :? TypeDefOrRef as ty ->
                yield! ty.Resolve().InstanceFields
            | _ ->
                failwith "TypeDef.AllInstanceFields: not implemented for TypeSpec in inheritence chain"
    |]
    member x.AllInstanceFields : FieldDef array =
        Array.append x.InheritedInstanceFields x.InstanceFields

    member x.StaticFields = Array.filter (fun (f : FieldDef) -> f.IsStatic) x.Fields

    member x.Methods =
        let lastMethodIndex =
            let isLastTypeDef = rowIndex = mt.typeDefs.Length - 1
            if isLastTypeDef then
                mt.methodDefs.Length - 1
            else
                mt.typeDefs.[rowIndex + 1].methodsIndex - 1

        [|for i in typeDefRow.methodsIndex .. lastMethodIndex -> new MethodDef(assem, i)|]

    member x.Properties =
        let propMaps = mt.propertyMaps
        let propMapRowMatch (pmRow:PropertyMapRow) = pmRow.parentIndex = rowIndex
        match Array.tryFindIndex propMapRowMatch propMaps with
        | None -> [||]
        | Some propMapIndex ->
            let firstPropIndex = propMaps.[propMapIndex].propertyListIndex
            let lastPropIndex =
                if propMapIndex < propMaps.Length - 1 then
                    propMaps.[propMapIndex + 1].propertyListIndex - 1
                else
                    mt.properties.Length - 1

            [|for i in firstPropIndex .. lastPropIndex -> new Property(assem, i)|]

    member x.TypeKind : TypeKind =

        // From partition II section 22.37
        // There is one system-defined root, System.Object. All Classes and ValueTypes shall
        // derive, ultimately, from System.Object; Classes can derive from other Classes
        // (through a single, non-looping chain) to any depth required.
        //
        // Interfaces do not inherit from one another; however, they can have zero or more
        // required interfaces, which shall be implemented. The Interface requirement chain
        // is shown as light, dashed arrows. This includes links between Interfaces and
        // Classes/ValueTypes – where the latter are said to implement that interface or
        // interfaces.
        //
        // Regular ValueTypes (i.e., excluding Enums – see later) are defined as deriving
        // directly from System.ValueType. Regular ValueTypes cannot be derived to a depth
        // of more than one. (Another way to state this is that user-defined ValueTypes
        // shall be sealed.) User-defined Enums shall derive directly from System.Enum. Enums
        // cannot be derived to a depth of more than one below System.Enum. (Another way to
        // state this is that user-defined Enums shall be sealed.) System.Enum derives
        // directly from System.ValueType.
        //
        // User-defined delegates derive from System.Delegate. Delegates cannot be derived
        // to a depth of more than one.
        
        if x.IsInterface then
            TypeKind.Interface
        else
            // TODO is this approach robust?
            let immediateKindOf (t : TypeDefOrRef) =
                match t.Namespace, t.Name with
                | Some "System", "Object" -> Some TypeKind.Class
                | Some "System", "ValueType" -> Some TypeKind.Valuetype
                | Some "System", "Delegate" -> Some TypeKind.Delegate
                | Some "System", "Enum" -> Some TypeKind.Enum
                | _ -> None
            match immediateKindOf x with
            | Some tk -> tk
            | None ->
                match x.Extends with
                | Some (:? TypeDefOrRef as ext) ->
                    match immediateKindOf ext with
                    | Some tk -> tk
                    | None -> TypeKind.Class
                | Some ext ->
                    //failwithf "Don't know how to deal with extention type %A" ext
                    printfn "TODO figure out the type kind of %A" ext
                    TypeKind.Class
                | None -> failwith "we should never reach this error"

    member x.IsValueType =
        match x.TypeKind with
        | TypeKind.Valuetype | TypeKind.Enum -> true
        | _ -> false

    override x.SizeBytes =
        match x.ClassLayout with
        | Some {ClassLayoutRow.classSize = s} -> Some (int s)
        | None ->
            let fields = x.Fields
            let rec accumSum (i : int) (sum : int) =
                if i < fields.Length then
                    match fields.[i].Signature.fType.SizeBytes with
                    | None -> None
                    | Some s -> accumSum (i + 1) (sum + s)
                else
                    Some sum

            accumSum 0 0

    override x.AsTypeBlob ( (*unbox:bool*) ) : TypeBlob option =
        let asClassOrVal() =
            match x.TypeKind with
            | TypeKind.Interface ->
                None
            | TypeKind.Class | TypeKind.Delegate ->
                Some (TypeBlob.Class x)
            | TypeKind.Valuetype | TypeKind.Enum ->
                Some (TypeBlob.ValueType x)
        //if unbox then
        match x.Namespace with
        | Some "System" ->
            match x.Name with
            | "Boolean"         -> Some TypeBlob.Boolean
            | "Char"            -> Some TypeBlob.Char
            | "Object"          -> Some TypeBlob.Object
            | "String"          -> Some TypeBlob.String
            | "Single"          -> Some TypeBlob.R4
            | "Double"          -> Some TypeBlob.R8
            | "SByte"           -> Some TypeBlob.I1
            | "Int16"           -> Some TypeBlob.I2
            | "Int32"           -> Some TypeBlob.I4
            | "Int64"           -> Some TypeBlob.I8
            | "IntPtr"          -> Some TypeBlob.I
            | "UIntPtr"         -> Some TypeBlob.U
            | "Byte"            -> Some TypeBlob.U1
            | "UInt16"          -> Some TypeBlob.U2
            | "UInt32"          -> Some TypeBlob.U4
            | "UInt64"          -> Some TypeBlob.U8
            | _                 -> asClassOrVal()
        | _ ->
            asClassOrVal()
        //else
        //    asClassOrVal()

    member x.IsPrimitive =
        match x.AsTypeBlob() (*true*) with
        | Some tb -> tb.IsPrimitive
        | None -> false

    override x.AsIntermediateType() = x.AsTypeBlob( (*false*) ).Value.AsIntermediateType()

and Property(assem:Assembly, rowIndex) =
    let mt = assem.MetadataTables
    let propRow = mt.properties.[rowIndex]
    let methSems =
        let methSemMatch (msRow:MethodSemanticsRow) =
            msRow.assocIndex = rowIndex
            && msRow.assocKind = MetadataTableKind.PropertyKind
        [|for i = 0 to mt.methodSemantics.Length - 1 do
            if methSemMatch mt.methodSemantics.[i] then
                yield new PropertyMethodSemantics(assem, i)|]

    member x.MethodSemantics = methSems
    member x.Name = propRow.name
    member x.Signature =
        let blob = ref(assem.ReadBlobAtIndex propRow.typeIndex |> List.ofArray)
        PropertySig.FromBlob assem blob

and PropertyMethodSemantics(assem:Assembly, rowIndex:int) =
    let msRow = assem.MetadataTables.methodSemantics.[rowIndex]

    member x.PropKind = PropKind.FromFlags msRow.semanticsFlags
    member x.Method = new MethodDef(assem, msRow.methodIndex)

and [<RequireQualifiedAccess>] PropKind = Getter | Setter | Other
with
    static member FromFlags (flags:uint16) =
        match flags with
        | 0x0001us -> Setter
        | 0x0002us -> Getter
        | 0x0004us -> Other
        | _ -> failwithf "unexpected property method kind flag 0x%X" flags

and [<RequireQualifiedAccess>] GenericParamVariance = None | Covariant | Contravariant

and [<RequireQualifiedAccess>] SpecialConstraint =
    | None
    | ReferenceType
    | NotNullableValueType
    | DefaultConstructor

and GenericParam(assem : Assembly, rowIndex : int) =
    let mt = assem.MetadataTables
    let gpRow = mt.genericParams.[rowIndex]

    let isFlagSet mask = gpRow.flags &&& mask <> 0us

    member x.Number = gpRow.number
    member x.Name = gpRow.name

    member x.Variance =
        match gpRow.flags &&& 0x0003us with
        | 0x0000us -> GenericParamVariance.None
        | 0x0001us -> GenericParamVariance.Covariant
        | 0x0002us -> GenericParamVariance.Contravariant
        | gpv -> failwithf "bad generic param variance value: %X" gpv

    member x.ReferenceTypeConstrained = isFlagSet 0x0004us
    member x.NotNullableValueTypeConstrained = isFlagSet 0x0008us
    member x.DefaultConstructorConstrained = isFlagSet 0x0010us

    member x.Constraints : seq<TypeDefRefOrSpec> = seq {
        for gpc in mt.genericParamConstraints do
            if gpc.ownerIndex = rowIndex then
                yield
                    match gpc.constraintKind with
                    | MetadataTableKind.TypeDefKind ->
                        upcast new TypeDef(assem, gpc.ownerIndex)
                    | MetadataTableKind.TypeRefKind ->
                        upcast new TypeRef(assem, gpc.ownerIndex)
                    | MetadataTableKind.TypeSpecKind ->
                        upcast new TypeSpec(assem, gpc.ownerIndex)
                    | ck ->
                        failwithf "bad constraint kind: %A" ck
    }

and [<RequireQualifiedAccess>] CodeType = IL | Native | Runtime

and [<RequireQualifiedAccess>] MemberAccess =
    | CompilerControlled
    | Private
    | FamANDAssem
    | Assem
    | Family
    | FamORAssem
    | Public
    with
        static member FromUShort (i : uint16) =
            // The MemberAccessMask (23.1.10) subfield of Flags shall contain precisely one of
            // CompilerControlled, Private, FamANDAssem, Assem, Family, FamORAssem, or Public
            match i &&& 0x0007us with
            | 0x0000us -> MemberAccess.CompilerControlled
            | 0x0001us -> MemberAccess.Private
            | 0x0002us -> MemberAccess.FamANDAssem
            | 0x0003us -> MemberAccess.Assem
            | 0x0004us -> MemberAccess.Family
            | 0x0005us -> MemberAccess.FamORAssem
            | 0x0006us -> MemberAccess.Public
            | n -> failwithf "bad MemberAccess value: 0x%X" n

        override x.ToString() =
            match x with
            | MemberAccess.Assem -> "assembly"
            | MemberAccess.CompilerControlled -> "compilercontrolled"
            | MemberAccess.FamANDAssem -> "famandassem"
            | MemberAccess.Family -> "family"
            | MemberAccess.FamORAssem -> "famorassem"
            | MemberAccess.Private -> "private"
            | MemberAccess.Public -> "public"

and Parameter (name:string, sequence:int, pType:Param) =

    new(pRow:ParamRow, pType:Param) = Parameter(pRow.name, int pRow.sequence, pType)

    member x.Name = name
    member x.Sequence = sequence
    member x.CustomMods = pType.customMods
    member x.Type = pType

and [<AbstractClass>] Method() =
    abstract Name : string with get
    abstract Resolve : unit -> MethodDef
    abstract Signature : MethodDefOrRefSig with get
    abstract CilId : assemCtxt:AssemblyBase -> string

    static member FromKindAndIndex (assem : Assembly) (kind : MetadataTableKind) (i : int) : Method =
        match kind with
        | MetadataTableKind.MethodDefKind -> upcast new MethodDef(assem, i)
        | MetadataTableKind.MethodSpecKind -> upcast new MethodSpec(assem, i)
        | MetadataTableKind.MemberRefKind -> upcast new MethodRef(assem, i)
        | _ -> failwith "failed to convert token into a method"

    static member FromMetadataToken (assem : Assembly) (mt : MetadataToken) : Method =
        match mt with
        | Some tableKind, i -> Method.FromKindAndIndex assem tableKind i
        | None, _ -> failwith "failed to convert token into a method"

    /// determines if method signatures match assuming
    /// that the type is owning type is the same
    static member SignaturesMatch (meth1 : Method) (meth2 : Method) =
        if meth1.Name <> meth2.Name then
            false
        else
            let sig1 = meth1.Signature
            let sig2 = meth2.Signature

            let rec paramsMatch (params1 : Param list) (params2 : Param list) =
                match params1, params2 with
                | [], [] -> true
                | p1 :: p1Tail, p2 :: p2Tail -> Param.ParamsMatch p1 p2 && paramsMatch p1Tail p2Tail
                | _ -> false

            paramsMatch sig1.methParams sig2.methParams

and MethodSpec (assem : Assembly, rowIndex : int) =
    inherit Method()

    let mt = assem.MetadataTables
    let msRow = mt.methodSpecs.[rowIndex]
    let meth = Method.FromKindAndIndex assem msRow.methodKind msRow.methodIndex

    override x.Name = meth.Name
    override x.Resolve() = meth.Resolve()
    override x.Signature = meth.Signature
    override x.CilId(assemCtxt : AssemblyBase) = "TODO implement CilId for MethodSpec"

and MethodRef (assem : Assembly, rowIndex : int) =
    inherit Method()

    let mt = assem.MetadataTables
    let mrRow = mt.memberRefs.[rowIndex]

    override x.Name = mrRow.name
    override x.Resolve() =
        let matchingMethodIn (ty : TypeDefOrRef) =
            let ty = ty.Resolve()
            match Array.filter (Method.SignaturesMatch x) ty.Methods with
            | [|matchingMeth|] -> matchingMeth
            | matches -> failwithf "expected a single method match for %s but got %i" x.Name matches.Length

        match mrRow.classKind with
        | MetadataTableKind.MethodDefKind -> failwithf "TODO implement %A for method ref" mrRow.classKind
        | MetadataTableKind.ModuleRefKind -> failwithf "TODO implement %A for method ref" mrRow.classKind
        | MetadataTableKind.TypeDefKind -> failwithf "TODO implement %A for method ref" mrRow.classKind
        | MetadataTableKind.TypeRefKind -> matchingMethodIn <| new TypeRef(assem, mrRow.classIndex)
        | MetadataTableKind.TypeSpecKind ->
            let tySpec = new TypeSpec(assem, mrRow.classIndex)
            match tySpec.TypeSpecBlob with
            | TypeSpecBlob.GenericInst genTyInst ->
                match genTyInst.genericType with
                | :? TypeDefOrRef as ty -> matchingMethodIn ty
                | ty -> failwithf "TODO sorry I don't do %A yet" ty
            | _ ->
                failwithf "TODO implement %A (%A) for method ref" mrRow.classKind tySpec.TypeSpecBlob
        | kind -> failwithf "invalid class kind for method ref: %A" kind
    override x.Signature =
        let blob = ref(assem.ReadBlobAtIndex mrRow.signatureIndex |> List.ofArray)
        MethodDefOrRefSig.FromBlob assem blob
    override x.CilId(assemCtxt : AssemblyBase) = x.Resolve().CilId(assemCtxt)
    override x.ToString() = "MethodRef(" + x.CilId assem + ")"

and MethodDef (assem : Assembly, rowIndex : int) =
    inherit Method()

    let mt = assem.MetadataTables
    let mdRow = mt.methodDefs.[rowIndex]
    let isFlagSet mask = mdRow.flags &&& mask <> 0us
    let isImplFlagSet mask = mdRow.implFlags &&& mask <> 0us

    let readLocalVars (localVarSigTok : uint32) : LocalVarSig array =
        // A LocalVarSig is indexed by the StandAloneSig.Signature column.
        // It captures the type of all the local variables in a method.
        if localVarSigTok = 0u then
            [||]
        else
            match toMetadataToken localVarSigTok with
            | Some MetadataTableKind.StandAloneSigKind, row ->
                let sigRow = mt.standAloneSigs.[row]
                let blob = ref(assem.ReadBlobAtIndex sigRow.signatureIndex |> List.ofArray)
                LocalVarSig.FromBlob assem blob
            | tblKind, _ ->
                failwithf "Unexpected table kind for localVarSigTok: %A" tblKind

    let readMethodBody (r : BinaryReader) =
        let fstByte = r.ReadByte ()

        let isTinyFmt =
            match fstByte &&& 0x03uy with
            | 0x02uy -> true
            | 0x03uy -> false
            | n -> failwithf "bad method body format 0x%X" n

        if isTinyFmt then
            let mbSize = fstByte >>> 2
            //debugfn "tiny header: size=%i" mbSize

            {
                MethodBody.maxStack = 8us
                initLocals = false
                locals = [||]
                blocks = AbstInst.toAbstInstBlocks assem (readInsts r (uint32 mbSize))
                exceptionClauses = [||]
            }
        else
            let moreSects = fstByte &&& 0x08uy <> 0uy
            let initLocals = fstByte &&& 0x10uy <> 0uy
            let headerSize = r.ReadByte () >>> 4
            if headerSize <> 3uy then
                failwith "expected method body header size to be 3 but it's %i" headerSize
            let maxStack = r.ReadUInt16 ()
            let codeSize = r.ReadUInt32 ()
            let localVarSigTok = r.ReadUInt32 ()

            (*debugfn
                "fat header: moreSects=%b, initLocals=%b, headerSize=%i, maxStack=%i, codeSize=%i, localVarSigTok=%i"
                moreSects
                initLocals
                headerSize
                maxStack
                codeSize
                localVarSigTok*)

            let insts = readInsts r codeSize
            let exceptionSecs = ExceptionClause.ReadExceptionSections r moreSects codeSize
            let locals = readLocalVars localVarSigTok

            {
                MethodBody.maxStack = maxStack
                initLocals = initLocals
                locals = locals
                blocks = AbstInst.toAbstInstBlocks assem insts
                exceptionClauses = exceptionSecs
            }

    let signature =
        lazy (
            let blob = ref(assem.ReadBlobAtIndex mdRow.signatureIndex |> List.ofArray)
            MethodDefOrRefSig.FromBlob assem blob
        )

    override x.GetHashCode() = rowIndex ^^^ assem.GetHashCode()
    override x.Equals otherObj =
        match otherObj with
        | :? MethodDef as otherMeth ->
            rowIndex = otherMeth.RowIndex && assem = otherMeth.Assembly
        | _ ->
            false

    override x.Name = mdRow.name
    override x.Resolve() = x
    override x.Signature = signature.Value
    override x.CilId(assemCtxt : AssemblyBase) =
        let maybeQuotedName =
            if x.Name.Contains "." then
                "'" + x.Name + "'"
            else
                x.Name
        spaceSepStrs [|
            if not x.IsStatic then yield "instance"
            yield x.Signature.retType.CilId(assemCtxt)
            yield x.DeclaringType.CilId(true, assemCtxt) + "::" + maybeQuotedName + "("
            yield commaSepStrs [|
                for p in x.Signature.methParams do
                    yield spaceSepStrs [|
                        for cm in p.customMods do
                            yield cm.CilId(assemCtxt)
                        yield p.pType.CilId(assemCtxt)
                    |]
            |]
            yield ")"
        |]
    override x.ToString() = "MethodDef(" + x.CilId assem + ")"
    
    member x.FullName = x.DeclaringType.FullName + "::" + x.Name

    member x.Assembly   = assem
    member x.RowIndex   = rowIndex

    member x.TableRow   = mdRow
    member x.IsCtor     = mdRow.name = ".ctor"
    member x.IsCCtor    = mdRow.name = ".cctor"
    
    member x.CodeType =
        // Section 22.26 item 34.b
        // ImplFlags.CodeTypeMask shall have exactly one of the following values:
        // Native,  CIL, or Runtime
        match mdRow.implFlags &&& 0x0003us with
        | 0x0000us -> CodeType.IL
        | 0x0001us -> CodeType.Native
        | 0x0003us -> CodeType.Runtime
        | n -> failwithf "bad CodeTypeMask value: 0x%X" n

    member x.IsManaged      = not (isImplFlagSet 0x0004us)
    member x.IsForwardRef   = isImplFlagSet 0x0010us
    member x.IsSynchronized = isImplFlagSet 0x0020us
    member x.NoInlining     = isImplFlagSet 0x0008us
    member x.NoOptimization = isImplFlagSet 0x0040us

    member x.MemberAccess = MemberAccess.FromUShort mdRow.flags

    // Section 22.26 item 7. The following combined bit settings in Flags are invalid
    // a. Static | Final
    // b. Static | Virtual
    // c. Static | NewSlot
    // d. Final  | Abstract
    // e. Abstract | PinvokeImpl
    // f. CompilerControlled | SpecialName
    // g. CompilerControlled | RTSpecialName
    member x.IsStatic       = isFlagSet 0x0010us
    member x.IsFinal        = isFlagSet 0x0020us
    member x.IsVirtual      = isFlagSet 0x0040us
    member x.HideBySig      = isFlagSet 0x0080us
    member x.NewVTableSlot  = isFlagSet 0x0100us
    member x.IsStrict       = isFlagSet 0x0200us
    member x.IsAbstract     = isFlagSet 0x0400us
    member x.SpecialName    = isFlagSet 0x0800us
    member x.HasPInvokeImpl = isFlagSet 0x2000us
    member x.RTSpecialName  = isFlagSet 0x1000us
    member x.HasSecurity    = isFlagSet 0x4000us
    member x.RequireSecObj  = isFlagSet 0x8000us

    member x.Parameters =
        let lastParamIndex =
            let isLastMethodDef = rowIndex = mt.methodDefs.Length - 1
            if isLastMethodDef then
                mt.paramRows.Length - 1
            else
                mt.methodDefs.[rowIndex + 1].paramIndex - 1
        let r = assem.Reader
        let methParamBlobs = x.Signature.methParams
        if methParamBlobs.Length <> 1 + lastParamIndex - mdRow.paramIndex then
            failwithf
                "signature length (%i) not equal to parameter length (%i)"
                methParamBlobs.Length
                (1 + lastParamIndex - mdRow.paramIndex)
        [|
            for i in 0 .. methParamBlobs.Length - 1 ->
                new Parameter(mt.paramRows.[mdRow.paramIndex + i], methParamBlobs.[i])
        |]

    member x.ReturnType = x.Signature.retType

    member x.HasMethodBody = mdRow.rva <> 0u
    member x.MethodBody =
        if mdRow.rva = 0u then
            // Section 22.26 item 33. If RVA = 0, then either:
            // * Flags.Abstract = 1, or
            // * ImplFlags.Runtime = 1, or
            // * Flags.PinvokeImpl = 1
            if not (x.IsAbstract || x.CodeType = CodeType.Runtime || x.HasPInvokeImpl) then
                failwith "bad method body RVA"
            None
        else
            // Section 22.26 item 34. If RVA != 0, then:
            // a. Flags.Abstract shall be 0, and
            // b. ImplFlags.CodeTypeMask shall have exactly one of the following values: Native,  CIL, or
            //    Runtime, and
            // c. RVA shall point into the CIL code stream in this file
            // TODO check these conditions

            let r = assem.Reader
            r.BaseStream.Seek (assem.RVAToDiskPos mdRow.rva, SeekOrigin.Begin) |> ignore

            Some (readMethodBody r)

    member x.DeclaringType : TypeDef =
        let tdRows = mt.typeDefs
        let rec findDecTy (currIndex : int) =
            let foundType =
                currIndex = tdRows.Length - 1
                || rowIndex < tdRows.[currIndex + 1].methodsIndex
            if foundType then
                new TypeDef(assem, currIndex)
            else
                findDecTy (currIndex + 1)
        findDecTy 0

    member x.PInvokeInfo : PInvokeInfo option =
        if x.HasPInvokeImpl then
            let implMaps = mt.implMaps
            let rec go i =
                if i < implMaps.Length then
                    let currImplMap = implMaps.[i]
                    match currImplMap.memberForwardedKind with
                    | MetadataTableKind.MethodDefKind when currImplMap.memberForwardedIndex = i ->
                        i
                    | _ ->
                        go (i + 1)
                else
                    let decName = x.DeclaringType.FullName
                    failwithf "failed to find PInvokeInfo for %s::%s" decName x.Name
            Some <| new PInvokeInfo(assem, go 0)
        else
            None

    member x.HasThis =
        // TODO figure out what explicit this means
        
        // TODO this is strange. understand why it isn't good enough to just look
        // at x.Signature.thisKind
        let simpleCheck() =
            match x.Signature.thisKind with
            | ThisKind.HasThis -> true
            | _ -> false

        if x.HasMethodBody then
            simpleCheck()
        else
            match x.CodeType, x.HasPInvokeImpl with
            | CodeType.IL, true -> false
            | (ct, hasPI) ->
                failwithf "no impl yet for HasThis where CodeType=%A and HasPInvokeImpl=%b" ct hasPI


    member x.ThisParam : Parameter option =
        if x.HasThis then
            let thisTy =
                match x.DeclaringType.AsTypeBlob( (*false*) ) with
                | None -> failwith "expected a valid \"this\" type blob"
                | Some declTy ->
                    if declTy.IsValType then
                        TypeBlob.Ptr([], Some declTy)
                    else
                        declTy
            
            let pType = {
                Param.customMods = []
                pType = ParamType.MayByRefTy {MaybeByRefType.isByRef = false; ty = thisTy}
            }

            Some (new Parameter("this", -1, pType))
        else
            None

    member x.AllParameters = [|
        match x.ThisParam with
        | Some tp -> yield tp
        | None -> ()

        yield! x.Parameters
    |]

    member x.Locals =
        match x.MethodBody with
        | Some body -> body.locals
        | None -> [||]

and MethodBody = {
    maxStack : uint16
    initLocals : bool
    locals : LocalVarSig array
    blocks : (AbstInst * uint32) array array
    exceptionClauses : ExceptionClause array array
}

and [<RequireQualifiedAccess>] CharSet = NotSpec | Ansi | Unicode | Auto
and [<RequireQualifiedAccess>] CallConv = Platformapi | Cdecl | Stdcall | Thiscall | Fastcall
and PInvokeInfo(assem:Assembly, rowIndex:int) =
    let mt = assem.MetadataTables
    let implMapRow = mt.implMaps.[rowIndex]

    member x.NoMangle = implMapRow.mappingFlags &&& 0x0001us <> 0us
    member x.SupportsLastError = implMapRow.mappingFlags &&& 0x0040us <> 0us
    member x.CharSet =
        match implMapRow.mappingFlags &&& 0x0006us with
        | 0x0000us -> CharSet.NotSpec
        | 0x0002us -> CharSet.Ansi
        | 0x0004us -> CharSet.Unicode
        | 0x0006us -> CharSet.Auto
        | v -> failwithf "unexpected charset bits 0x%X" v

    member x.CallConv =
        match implMapRow.mappingFlags &&& 0x0700us with
        | 0x0100us -> CallConv.Platformapi
        | 0x0200us -> CallConv.Cdecl
        | 0x0300us -> CallConv.Stdcall
        | 0x0400us -> CallConv.Thiscall
        | 0x0500us -> CallConv.Fastcall
        | v -> failwithf "unexpected callconv bits 0x%X" v

    member x.ImportName = implMapRow.importName

    member x.ModuleRef = new ModuleRef(assem, implMapRow.importScopeIndex)

and Call(tail : bool, meth : Method) =
    member x.Tail = tail
    member x.Method = meth
    override x.ToString() =
        let methStr = meth.ToString()
        if tail then
            "TailCall(" + methStr + ")"
        else
            "Call(" + methStr + ")"
and VirtCall(thisType : TypeDefRefOrSpec option, tail : bool, meth : Method) =
    inherit Call(tail, meth)
    member x.ThisType = thisType
    override x.ToString() =
        let methStr = meth.ToString()
        if tail then
            "TailVirtCall(" + methStr + ")"
        else
            "VirtCall(" + methStr + ")"

and [<RequireQualifiedAccess>] AbstInst =
    | Add
    | And
    | Beq of int
    | Bge of int
    | Bgt of int
    | Ble of int
    | Blt of int
    | BneUn of int
    | BgeUn of int
    | BgtUn of int
    | BleUn of int
    | BltUn of int
    | Br of int
    | Break
    | Brfalse of int
    | Brtrue of int
    | Call of Call
    | Calli of Call
    | Callvirt of VirtCall
    | ConvI1
    | ConvI2
    | ConvI4
    | ConvI8
    | ConvR4
    | ConvR8
    | ConvU4
    | ConvU8
    | Cpobj of TypeDefRefOrSpec
    | Div
    | DivUn
    | Dup
    | Jmp of MetadataToken
    | Ldarg of uint16
    | Ldarga of uint16
    | LdcI4 of int
    | LdcI8 of int64
    | LdcR4 of single
    | LdcR8 of double
    | LdindI1 of byte option * bool
    | LdindU1 of byte option * bool
    | LdindI2 of byte option * bool
    | LdindU2 of byte option * bool
    | LdindI4 of byte option * bool
    | LdindU4 of byte option * bool
    | LdindI8 of byte option * bool
    | LdindI of byte option * bool
    | LdindR4 of byte option * bool
    | LdindR8 of byte option * bool
    | LdindRef of byte option * bool
    | Ldloc of uint16
    | Ldloca of uint16
    | Ldnull
    | Ldobj of byte option * bool * TypeDefRefOrSpec
    | Ldstr of string
    | Mul
    | Neg
    | Nop
    | Not
    | Newobj of Method
    | Or
    | Pop
    | Rem
    | RemUn
    | Ret
    | Shl
    | Shr
    | ShrUn
    | Starg of uint16
    | StindRef of byte option * bool
    | StindI1 of byte option * bool
    | StindI2 of byte option * bool
    | StindI4 of byte option * bool
    | StindI8 of byte option * bool
    | StindR4 of byte option * bool
    | StindR8 of byte option * bool
    | Stloc of uint16
    | Sub
    | Switch of int array
    | Xor
    | Castclass of TypeDefRefOrSpec
    | Isinst of TypeDefRefOrSpec
    | ConvRUn
    | Unbox of TypeDefRefOrSpec
    | Throw
    | Ldfld of byte option * bool * FieldDefOrRef
    | Ldflda of byte option * bool * FieldDefOrRef
    | Stfld of byte option * bool * FieldDefOrRef
    | Ldsfld of bool * FieldDefOrRef
    | Ldsflda of bool * FieldDefOrRef
    | Stsfld of bool * FieldDefOrRef
    | Stobj of byte option * bool * TypeDefRefOrSpec
    | ConvOvfI1Un
    | ConvOvfI2Un
    | ConvOvfI4Un
    | ConvOvfI8Un
    | ConvOvfU1Un
    | ConvOvfU2Un
    | ConvOvfU4Un
    | ConvOvfU8Un
    | ConvOvfIUn
    | ConvOvfUUn
    | Box of TypeDefRefOrSpec
    | Newarr of TypeDefRefOrSpec
    | Ldlen
    | Ldelema of TypeDefRefOrSpec
    | LdelemI1
    | LdelemU1
    | LdelemI2
    | LdelemU2
    | LdelemI4
    | LdelemU4
    | LdelemI8
    | LdelemI
    | LdelemR4
    | LdelemR8
    | LdelemRef
    | StelemI
    | StelemI1
    | StelemI2
    | StelemI4
    | StelemI8
    | StelemR4
    | StelemR8
    | StelemRef
    | Ldelem of TypeDefRefOrSpec
    | Stelem of TypeDefRefOrSpec
    | UnboxAny of TypeDefRefOrSpec
    | ConvOvfI1
    | ConvOvfU1
    | ConvOvfI2
    | ConvOvfU2
    | ConvOvfI4
    | ConvOvfU4
    | ConvOvfI8
    | ConvOvfU8
    | Refanyval of MetadataToken
    | Ckfinite
    | Mkrefany of MetadataToken
    | Ldtoken of MetadataToken
    | ConvU2
    | ConvU1
    | ConvI
    | ConvOvfI
    | ConvOvfU
    | AddOvf
    | AddOvfUn
    | MulOvf
    | MulOvfUn
    | SubOvf
    | SubOvfUn
    | Endfinally
    | Leave of int
    | StindI of byte option * bool
    | ConvU
    | Arglist
    | Ceq
    | Cgt
    | CgtUn
    | Clt
    | CltUn
    | Ldftn of Method
    | Ldvirtftn of MetadataToken
    | Localloc
    | Endfilter
    | Initobj of TypeDefRefOrSpec
    | Cpblk of bool
    | Initblk of byte option * bool
    | Rethrow
    | Sizeof of TypeDefRefOrSpec
    | Refanytype
    with
        static member toAbstInstBlocks
                (assem : Assembly)
                (instsWithSizes : array<RawInst * uint32>)
                : (AbstInst * uint32) array array =

            let numInsts = instsWithSizes.Length
            let insts, sizes = Array.unzip instsWithSizes
            let instPositions = Array.scan (+) 0u sizes
            let instPositions = instPositions.[0 .. numInsts - 1]

            let tgtToInstIndex (srcInstIndex : int) (relTgt : int) =
                let currInstPos = instPositions.[srcInstIndex]
                let nextInstPos = currInstPos + sizes.[srcInstIndex]
                let absTgtPos = int nextInstPos + relTgt

                if absTgtPos < 0 then
                    failwithf "bad instruction position: %i, valid positions are: %A" absTgtPos instPositions

                let posIndex = System.Array.BinarySearch (instPositions, uint32 absTgtPos)
                if posIndex >= 0 then
                    posIndex
                else
                    failwithf "bad instruction position: %i, valid positions are: %A" absTgtPos instPositions

            // calculate block starts
            // TODO what about throws/rethrows etc. Should they end blocks?
            let blockStarts = ref (Set.singleton 0)
            for instIndex = 0 to insts.Length - 1 do
                let addNextInst() =
                    if instIndex + 1 < insts.Length then
                        blockStarts := (!blockStarts).Add(instIndex + 1)
                let addTgt (relTgt : int) =
                    blockStarts := (!blockStarts).Add(tgtToInstIndex instIndex relTgt)
                match insts.[instIndex] with
                | RawInst.Beq tgt | RawInst.Bge tgt | RawInst.Bgt tgt | RawInst.Ble tgt
                | RawInst.Blt tgt | RawInst.BneUn tgt | RawInst.BgeUn tgt | RawInst.BgtUn tgt
                | RawInst.BleUn tgt | RawInst.BltUn tgt | RawInst.Br tgt | RawInst.Brfalse tgt
                | RawInst.Brtrue tgt | RawInst.Leave tgt ->
                    addNextInst()
                    addTgt tgt
                | RawInst.Switch tgtArray ->
                    addNextInst()
                    Array.iter addTgt tgtArray
                | RawInst.Ret ->
                    addNextInst()
                | _ -> ()
            let blockStarts = Array.sort (Array.ofSeq !blockStarts)

            let tgtToBlkIndex (srcInstIndex : int) (relTgt : int) =
                let tgtInstIndex = tgtToInstIndex srcInstIndex relTgt
                let blkIndex = System.Array.BinarySearch (blockStarts, tgtInstIndex)
                if blkIndex >= 0 then
                    blkIndex
                else
                    failwithf "the target index (%i) does not point to a block start" tgtInstIndex
            
            let toAbstInst instIndex =
                match insts.[instIndex] with
                | RawInst.Add -> AbstInst.Add
                | RawInst.And -> AbstInst.And
                | RawInst.Beq tgt -> AbstInst.Beq (tgtToBlkIndex instIndex tgt)
                | RawInst.Bge tgt -> AbstInst.Bge (tgtToBlkIndex instIndex tgt)
                | RawInst.Bgt tgt -> AbstInst.Bgt (tgtToBlkIndex instIndex tgt)
                | RawInst.Ble tgt -> AbstInst.Ble (tgtToBlkIndex instIndex tgt)
                | RawInst.Blt tgt -> AbstInst.Blt (tgtToBlkIndex instIndex tgt)
                | RawInst.BneUn tgt -> AbstInst.BneUn (tgtToBlkIndex instIndex tgt)
                | RawInst.BgeUn tgt -> AbstInst.BgeUn (tgtToBlkIndex instIndex tgt)
                | RawInst.BgtUn tgt -> AbstInst.BgtUn (tgtToBlkIndex instIndex tgt)
                | RawInst.BleUn tgt -> AbstInst.BleUn (tgtToBlkIndex instIndex tgt)
                | RawInst.BltUn tgt -> AbstInst.BltUn (tgtToBlkIndex instIndex tgt)
                | RawInst.Br tgt -> AbstInst.Br (tgtToBlkIndex instIndex tgt)
                | RawInst.Break -> AbstInst.Break
                | RawInst.Brfalse tgt -> AbstInst.Brfalse (tgtToBlkIndex instIndex tgt)
                | RawInst.Brtrue tgt -> AbstInst.Brtrue (tgtToBlkIndex instIndex tgt)
                | RawInst.Call (isTail, metaTok) ->
                    let call = new Call(isTail, Method.FromMetadataToken assem metaTok)
                    AbstInst.Call call
                | RawInst.Calli (isTail, metaTok) ->
                    let call = new Call(isTail, Method.FromMetadataToken assem metaTok)
                    AbstInst.Calli call
                | RawInst.Callvirt (constrainedOpt, isTail, metaTok) ->
                    let meth = Method.FromMetadataToken assem metaTok
                    let constrTy = Option.map (TypeDefRefOrSpec.FromMetadataToken assem) constrainedOpt
                    let virtCall = new VirtCall(constrTy, isTail, meth)
                    AbstInst.Callvirt virtCall
                | RawInst.ConvI1 -> AbstInst.ConvI1
                | RawInst.ConvI2 -> AbstInst.ConvI2
                | RawInst.ConvI4 -> AbstInst.ConvI4
                | RawInst.ConvI8 -> AbstInst.ConvI8
                | RawInst.ConvR4 -> AbstInst.ConvR4
                | RawInst.ConvR8 -> AbstInst.ConvR8
                | RawInst.ConvU4 -> AbstInst.ConvU4
                | RawInst.ConvU8 -> AbstInst.ConvU8
                | RawInst.Cpobj typeMetaTok ->
                    AbstInst.Cpobj (TypeDefRefOrSpec.FromMetadataToken assem typeMetaTok)
                | RawInst.Div -> AbstInst.Div
                | RawInst.DivUn -> AbstInst.DivUn
                | RawInst.Dup -> AbstInst.Dup
                | RawInst.Jmp methodMetaTok -> AbstInst.Jmp methodMetaTok
                | RawInst.Ldarg argIndex -> AbstInst.Ldarg argIndex
                | RawInst.Ldarga argIndex -> AbstInst.Ldarga argIndex
                | RawInst.LdcI4 c -> AbstInst.LdcI4 c
                | RawInst.LdcI8 c -> AbstInst.LdcI8 c
                | RawInst.LdcR4 c -> AbstInst.LdcR4 c
                | RawInst.LdcR8 c -> AbstInst.LdcR8 c
                | RawInst.LdindI1 (unalignedOpt, volatilePrefix) -> AbstInst.LdindI1 (unalignedOpt, volatilePrefix)
                | RawInst.LdindU1 (unalignedOpt, volatilePrefix) -> AbstInst.LdindU1 (unalignedOpt, volatilePrefix)
                | RawInst.LdindI2 (unalignedOpt, volatilePrefix) -> AbstInst.LdindI2 (unalignedOpt, volatilePrefix)
                | RawInst.LdindU2 (unalignedOpt, volatilePrefix) -> AbstInst.LdindU2 (unalignedOpt, volatilePrefix)
                | RawInst.LdindI4 (unalignedOpt, volatilePrefix) -> AbstInst.LdindI4 (unalignedOpt, volatilePrefix)
                | RawInst.LdindU4 (unalignedOpt, volatilePrefix) -> AbstInst.LdindU4 (unalignedOpt, volatilePrefix)
                | RawInst.LdindI8 (unalignedOpt, volatilePrefix) -> AbstInst.LdindI8 (unalignedOpt, volatilePrefix)
                | RawInst.LdindI (unalignedOpt, volatilePrefix) -> AbstInst.LdindI (unalignedOpt, volatilePrefix)
                | RawInst.LdindR4 (unalignedOpt, volatilePrefix) -> AbstInst.LdindR4 (unalignedOpt, volatilePrefix)
                | RawInst.LdindR8 (unalignedOpt, volatilePrefix) -> AbstInst.LdindR8 (unalignedOpt, volatilePrefix)
                | RawInst.LdindRef (unalignedOpt, volatilePrefix) -> AbstInst.LdindRef (unalignedOpt, volatilePrefix)
                | RawInst.Ldloc varIndex -> AbstInst.Ldloc varIndex
                | RawInst.Ldloca varIndex -> AbstInst.Ldloca varIndex
                | RawInst.Ldnull -> AbstInst.Ldnull
                | RawInst.Ldobj (unalignedOpt, volatilePrefix, typeTok) ->
                    let ty = TypeDefRefOrSpec.FromMetadataToken assem typeTok
                    AbstInst.Ldobj (unalignedOpt, volatilePrefix, ty)
                | RawInst.Ldstr strTok ->
                    match strTok with
                    | None, strIndex -> AbstInst.Ldstr (assem.ReadUSAtIndex (uint32 strIndex))
                    | Some mtKind, _ ->
                        failwithf "expected string token metadata table kind to be 'None' but got '%A'" mtKind
                | RawInst.Mul -> AbstInst.Mul
                | RawInst.Neg -> AbstInst.Neg
                | RawInst.Nop -> AbstInst.Nop
                | RawInst.Not -> AbstInst.Not
                | RawInst.Newobj ctorTok -> AbstInst.Newobj (Method.FromMetadataToken assem ctorTok)
                | RawInst.Or -> AbstInst.Or
                | RawInst.Pop -> AbstInst.Pop
                | RawInst.Rem -> AbstInst.Rem
                | RawInst.RemUn -> AbstInst.RemUn
                | RawInst.Ret -> AbstInst.Ret
                | RawInst.Shl -> AbstInst.Shl
                | RawInst.Shr -> AbstInst.Shr
                | RawInst.ShrUn -> AbstInst.ShrUn
                | RawInst.Starg argIndex -> AbstInst.Starg argIndex
                | RawInst.StindRef (unalignedOpt, volatilePrefix) -> AbstInst.StindRef (unalignedOpt, volatilePrefix)
                | RawInst.StindI1 (unalignedOpt, volatilePrefix) -> AbstInst.StindI1 (unalignedOpt, volatilePrefix)
                | RawInst.StindI2 (unalignedOpt, volatilePrefix) -> AbstInst.StindI2 (unalignedOpt, volatilePrefix)
                | RawInst.StindI4 (unalignedOpt, volatilePrefix) -> AbstInst.StindI4 (unalignedOpt, volatilePrefix)
                | RawInst.StindI8 (unalignedOpt, volatilePrefix) -> AbstInst.StindI8 (unalignedOpt, volatilePrefix)
                | RawInst.StindR4 (unalignedOpt, volatilePrefix) -> AbstInst.StindR4 (unalignedOpt, volatilePrefix)
                | RawInst.StindR8 (unalignedOpt, volatilePrefix) -> AbstInst.StindR8 (unalignedOpt, volatilePrefix)
                | RawInst.Stloc varIndex -> AbstInst.Stloc varIndex
                | RawInst.Sub -> AbstInst.Sub
                | RawInst.Switch tgtArray -> AbstInst.Switch (Array.map (tgtToBlkIndex instIndex) tgtArray)
                | RawInst.Xor -> AbstInst.Xor
                | RawInst.Castclass typeTok ->
                    AbstInst.Castclass (TypeDefRefOrSpec.FromMetadataToken assem typeTok)
                | RawInst.Isinst typeTok ->
                    AbstInst.Isinst (TypeDefRefOrSpec.FromMetadataToken assem typeTok)
                | RawInst.ConvRUn -> AbstInst.ConvRUn
                | RawInst.Unbox valTypeTok ->
                    AbstInst.Unbox (TypeDefRefOrSpec.FromMetadataToken assem valTypeTok)
                | RawInst.Throw -> AbstInst.Throw
                | RawInst.Ldfld (unalignedOpt, volatilePrefix, fieldTok) ->
                    let field = FieldDefOrRef.FromMetadataToken assem fieldTok
                    AbstInst.Ldfld (unalignedOpt, volatilePrefix, field)
                | RawInst.Ldflda (unalignedOpt, volatilePrefix, fieldTok) ->
                    let field = FieldDefOrRef.FromMetadataToken assem fieldTok
                    AbstInst.Ldflda (unalignedOpt, volatilePrefix, field)
                | RawInst.Stfld (unalignedOpt, volatilePrefix, fieldTok) ->
                    let field = FieldDefOrRef.FromMetadataToken assem fieldTok
                    AbstInst.Stfld (unalignedOpt, volatilePrefix, field)
                | RawInst.Ldsfld (volatilePrefix, fieldTok) ->
                    let field = FieldDefOrRef.FromMetadataToken assem fieldTok
                    AbstInst.Ldsfld (volatilePrefix, field)
                | RawInst.Ldsflda (volatilePrefix, fieldTok) ->
                    let field = FieldDefOrRef.FromMetadataToken assem fieldTok
                    AbstInst.Ldsflda (volatilePrefix, field)
                | RawInst.Stsfld (volatilePrefix, fieldTok) ->
                    let field = FieldDefOrRef.FromMetadataToken assem fieldTok
                    AbstInst.Stsfld (volatilePrefix, field)
                | RawInst.Stobj (unalignedOpt, volatilePrefix, typeTok) ->
                    let ty = TypeDefRefOrSpec.FromMetadataToken assem typeTok
                    AbstInst.Stobj (unalignedOpt, volatilePrefix, ty)
                | RawInst.ConvOvfI1Un -> AbstInst.ConvOvfI1Un
                | RawInst.ConvOvfI2Un -> AbstInst.ConvOvfI2Un
                | RawInst.ConvOvfI4Un -> AbstInst.ConvOvfI4Un
                | RawInst.ConvOvfI8Un -> AbstInst.ConvOvfI8Un
                | RawInst.ConvOvfU1Un -> AbstInst.ConvOvfU1Un
                | RawInst.ConvOvfU2Un -> AbstInst.ConvOvfU2Un
                | RawInst.ConvOvfU4Un -> AbstInst.ConvOvfU4Un
                | RawInst.ConvOvfU8Un -> AbstInst.ConvOvfU8Un
                | RawInst.ConvOvfIUn -> AbstInst.ConvOvfIUn
                | RawInst.ConvOvfUUn -> AbstInst.ConvOvfUUn
                | RawInst.Box typeTok ->
                    AbstInst.Box (TypeDefRefOrSpec.FromMetadataToken assem typeTok)
                | RawInst.Newarr elemTypeTok ->
                    AbstInst.Newarr (TypeDefRefOrSpec.FromMetadataToken assem elemTypeTok)
                | RawInst.Ldlen -> AbstInst.Ldlen
                | RawInst.Ldelema elemTypeTok ->
                    AbstInst.Ldelema (TypeDefRefOrSpec.FromMetadataToken assem elemTypeTok)
                | RawInst.LdelemI1 -> AbstInst.LdelemI1
                | RawInst.LdelemU1 -> AbstInst.LdelemU1
                | RawInst.LdelemI2 -> AbstInst.LdelemI2
                | RawInst.LdelemU2 -> AbstInst.LdelemU2
                | RawInst.LdelemI4 -> AbstInst.LdelemI4
                | RawInst.LdelemU4 -> AbstInst.LdelemU4
                | RawInst.LdelemI8 -> AbstInst.LdelemI8
                | RawInst.LdelemI -> AbstInst.LdelemI
                | RawInst.LdelemR4 -> AbstInst.LdelemR4
                | RawInst.LdelemR8 -> AbstInst.LdelemR8
                | RawInst.LdelemRef -> AbstInst.LdelemRef
                | RawInst.StelemI -> AbstInst.StelemI
                | RawInst.StelemI1 -> AbstInst.StelemI1
                | RawInst.StelemI2 -> AbstInst.StelemI2
                | RawInst.StelemI4 -> AbstInst.StelemI4
                | RawInst.StelemI8 -> AbstInst.StelemI8
                | RawInst.StelemR4 -> AbstInst.StelemR4
                | RawInst.StelemR8 -> AbstInst.StelemR8
                | RawInst.StelemRef -> AbstInst.StelemRef
                | RawInst.Ldelem elemTypeTok ->
                    AbstInst.Ldelem (TypeDefRefOrSpec.FromMetadataToken assem elemTypeTok)
                | RawInst.Stelem elemTypeTok ->
                    AbstInst.Stelem (TypeDefRefOrSpec.FromMetadataToken assem elemTypeTok)
                | RawInst.UnboxAny typeTok ->
                    AbstInst.UnboxAny (TypeDefRefOrSpec.FromMetadataToken assem typeTok)
                | RawInst.ConvOvfI1 -> AbstInst.ConvOvfI1
                | RawInst.ConvOvfU1 -> AbstInst.ConvOvfU1
                | RawInst.ConvOvfI2 -> AbstInst.ConvOvfI2
                | RawInst.ConvOvfU2 -> AbstInst.ConvOvfU2
                | RawInst.ConvOvfI4 -> AbstInst.ConvOvfI4
                | RawInst.ConvOvfU4 -> AbstInst.ConvOvfU4
                | RawInst.ConvOvfI8 -> AbstInst.ConvOvfI8
                | RawInst.ConvOvfU8 -> AbstInst.ConvOvfU8
                | RawInst.Refanyval valTypeTok -> AbstInst.Refanyval valTypeTok
                | RawInst.Ckfinite -> AbstInst.Ckfinite
                | RawInst.Mkrefany typeTok -> AbstInst.Mkrefany typeTok
                | RawInst.Ldtoken metaTok -> AbstInst.Ldtoken metaTok
                | RawInst.ConvU2 -> AbstInst.ConvU2
                | RawInst.ConvU1 -> AbstInst.ConvU1
                | RawInst.ConvI -> AbstInst.ConvI
                | RawInst.ConvOvfI -> AbstInst.ConvOvfI
                | RawInst.ConvOvfU -> AbstInst.ConvOvfU
                | RawInst.AddOvf -> AbstInst.AddOvf
                | RawInst.AddOvfUn -> AbstInst.AddOvfUn
                | RawInst.MulOvf -> AbstInst.MulOvf
                | RawInst.MulOvfUn -> AbstInst.MulOvfUn
                | RawInst.SubOvf -> AbstInst.SubOvf
                | RawInst.SubOvfUn -> AbstInst.SubOvfUn
                | RawInst.Endfinally -> AbstInst.Endfinally
                | RawInst.Leave tgt -> AbstInst.Leave (tgtToBlkIndex instIndex tgt)
                | RawInst.StindI (unalignedOpt, volatilePrefix) -> AbstInst.StindI (unalignedOpt, volatilePrefix)
                | RawInst.ConvU -> AbstInst.ConvU
                | RawInst.Arglist -> AbstInst.Arglist
                | RawInst.Ceq -> AbstInst.Ceq
                | RawInst.Cgt -> AbstInst.Cgt
                | RawInst.CgtUn -> AbstInst.CgtUn
                | RawInst.Clt -> AbstInst.Clt
                | RawInst.CltUn -> AbstInst.CltUn
                | RawInst.Ldftn methodTok -> AbstInst.Ldftn (Method.FromMetadataToken assem methodTok)
                | RawInst.Ldvirtftn methodTok -> AbstInst.Ldvirtftn methodTok
                | RawInst.Localloc -> AbstInst.Localloc
                | RawInst.Endfilter -> AbstInst.Endfilter
                | RawInst.Initobj typeTok ->
                    AbstInst.Initobj (TypeDefRefOrSpec.FromMetadataToken assem typeTok)
                | RawInst.Cpblk volatilePrefix -> AbstInst.Cpblk volatilePrefix
                | RawInst.Initblk (unalignedOpt, volatilePrefix) -> AbstInst.Initblk (unalignedOpt, volatilePrefix)
                | RawInst.Rethrow -> AbstInst.Rethrow
                | RawInst.Sizeof typeTok ->
                    AbstInst.Sizeof (TypeDefRefOrSpec.FromMetadataToken assem typeTok)
                | RawInst.Refanytype -> AbstInst.Refanytype

            let instBlocks = [|
                for blkIndex = 0 to blockStarts.Length - 1 do
                    let firstInstIndex = blockStarts.[blkIndex]
                    let lastInstIndex =
                        if blkIndex = blockStarts.Length - 1 then
                            numInsts - 1
                        else
                            blockStarts.[blkIndex + 1] - 1

                    yield [|
                        for instIndex in firstInstIndex .. lastInstIndex ->
                            toAbstInst instIndex, sizes.[instIndex]
                    |]
            |]
            
            instBlocks

        /// true iff this type of instruction terminates a basic block
        member x.IsTerminal =
            match x with
            | Beq _ | Bge _ | Bgt _ | Ble _ | Blt _ | BneUn _ | BgeUn _ | BgtUn _
            | BleUn _ | BltUn _ | Br _ | Brfalse _ | Brtrue _ | Leave _
            | Switch _ | Ret ->
                true
            | _ ->
                false

        /// The following value should have valid stack push and pop parameters
        /// but the size in bytes for example may not correspond to the truth
        member private x.ArchetypeOpCode : OpCode =
            match x with
            | Add -> OpCodes.Add
            | And -> OpCodes.And
            | Beq  _ -> OpCodes.Beq
            | Bge  _ -> OpCodes.Bge
            | Bgt _ -> OpCodes.Bgt
            | Ble _ -> OpCodes.Ble
            | Blt _ -> OpCodes.Blt
            | BneUn _ -> OpCodes.Bne_Un
            | BgeUn _ -> OpCodes.Bge_Un
            | BgtUn _ -> OpCodes.Bgt_Un
            | BleUn _ -> OpCodes.Ble_Un
            | BltUn _ -> OpCodes.Blt_Un
            | Br _ -> OpCodes.Br
            | Break -> OpCodes.Break
            | Brfalse _ -> OpCodes.Brfalse
            | Brtrue _ -> OpCodes.Brtrue
            | Call _ -> OpCodes.Call
            | Calli _ -> OpCodes.Calli
            | Callvirt _ -> OpCodes.Callvirt
            | ConvI1 -> OpCodes.Conv_I1
            | ConvI2 -> OpCodes.Conv_I2
            | ConvI4 -> OpCodes.Conv_I4
            | ConvI8 -> OpCodes.Conv_I8
            | ConvR4 -> OpCodes.Conv_R4
            | ConvR8 -> OpCodes.Conv_R8
            | ConvU4 -> OpCodes.Conv_U4
            | ConvU8 -> OpCodes.Conv_U8
            | Cpobj _ -> OpCodes.Cpobj
            | Div -> OpCodes.Div
            | DivUn -> OpCodes.Div_Un
            | Dup -> OpCodes.Dup
            | Jmp _ -> OpCodes.Jmp
            | Ldarg _ -> OpCodes.Ldarg
            | Ldarga _ -> OpCodes.Ldarga
            | LdcI4 _ -> OpCodes.Ldc_I4
            | LdcI8 _ -> OpCodes.Ldc_I8
            | LdcR4 _ -> OpCodes.Ldc_R4
            | LdcR8 _ -> OpCodes.Ldc_R8
            | LdindI1 _ -> OpCodes.Ldind_I1
            | LdindU1 _ -> OpCodes.Ldind_U1
            | LdindI2 _ -> OpCodes.Ldind_I2
            | LdindU2 _ -> OpCodes.Ldind_U2
            | LdindI4 _ -> OpCodes.Ldind_I4
            | LdindU4 _ -> OpCodes.Ldind_U4
            | LdindI8 _ -> OpCodes.Ldind_I8
            | LdindI _ -> OpCodes.Ldind_I
            | LdindR4 _ -> OpCodes.Ldind_R4
            | LdindR8 _ -> OpCodes.Ldind_R8
            | LdindRef _ -> OpCodes.Ldind_Ref
            | Ldloc _ -> OpCodes.Ldloc
            | Ldloca _ -> OpCodes.Ldloca
            | Ldnull -> OpCodes.Ldnull
            | Ldobj _ -> OpCodes.Ldobj
            | Ldstr _ -> OpCodes.Ldstr
            | Mul -> OpCodes.Mul
            | Neg -> OpCodes.Neg
            | Nop -> OpCodes.Nop
            | Not -> OpCodes.Not
            | Newobj _ -> OpCodes.Newobj
            | Or -> OpCodes.Or
            | Pop -> OpCodes.Pop
            | Rem -> OpCodes.Rem
            | RemUn -> OpCodes.Rem_Un
            | Ret -> OpCodes.Ret
            | Shl -> OpCodes.Shl
            | Shr -> OpCodes.Shr
            | ShrUn -> OpCodes.Shr_Un
            | Starg _ -> OpCodes.Starg
            | StindRef _ -> OpCodes.Stind_Ref
            | StindI1 _ -> OpCodes.Stind_I1
            | StindI2 _ -> OpCodes.Stind_I2
            | StindI4 _ -> OpCodes.Stind_I4
            | StindI8 _ -> OpCodes.Stind_I8
            | StindR4 _ -> OpCodes.Stind_R4
            | StindR8 _ -> OpCodes.Stind_R8
            | Stloc _ -> OpCodes.Stloc
            | Sub -> OpCodes.Sub
            | Switch _ -> OpCodes.Switch
            | Xor -> OpCodes.Xor
            | Castclass _ -> OpCodes.Castclass
            | Isinst _ -> OpCodes.Isinst
            | ConvRUn -> OpCodes.Conv_R_Un
            | Unbox _ -> OpCodes.Unbox
            | Throw -> OpCodes.Throw
            | Ldfld _ -> OpCodes.Ldfld
            | Ldflda _ -> OpCodes.Ldflda
            | Stfld _ -> OpCodes.Stfld
            | Ldsfld _ -> OpCodes.Ldsfld
            | Ldsflda _ -> OpCodes.Ldsflda
            | Stsfld _ -> OpCodes.Stsfld
            | Stobj _ -> OpCodes.Stobj
            | ConvOvfI1Un -> OpCodes.Conv_Ovf_I1_Un
            | ConvOvfI2Un -> OpCodes.Conv_Ovf_I2_Un
            | ConvOvfI4Un -> OpCodes.Conv_Ovf_I4_Un
            | ConvOvfI8Un -> OpCodes.Conv_Ovf_I8_Un
            | ConvOvfU1Un -> OpCodes.Conv_Ovf_U1_Un
            | ConvOvfU2Un -> OpCodes.Conv_Ovf_U2_Un
            | ConvOvfU4Un -> OpCodes.Conv_Ovf_U4_Un
            | ConvOvfU8Un -> OpCodes.Conv_Ovf_U8_Un
            | ConvOvfIUn -> OpCodes.Conv_Ovf_I_Un
            | ConvOvfUUn -> OpCodes.Conv_Ovf_U_Un
            | Box _ -> OpCodes.Box
            | Newarr _ -> OpCodes.Newarr
            | Ldlen -> OpCodes.Ldlen
            | Ldelema _ -> OpCodes.Ldelema
            | LdelemI1 -> OpCodes.Ldelem_I1
            | LdelemU1 -> OpCodes.Ldelem_U1
            | LdelemI2 -> OpCodes.Ldelem_I2
            | LdelemU2 -> OpCodes.Ldelem_U2
            | LdelemI4 -> OpCodes.Ldelem_I4
            | LdelemU4 -> OpCodes.Ldelem_U4
            | LdelemI8 -> OpCodes.Ldelem_I8
            | LdelemI -> OpCodes.Ldelem_I
            | LdelemR4 -> OpCodes.Ldelem_R4
            | LdelemR8 -> OpCodes.Ldelem_R8
            | LdelemRef -> OpCodes.Ldelem_Ref
            | StelemI -> OpCodes.Stelem_I
            | StelemI1 -> OpCodes.Stelem_I1
            | StelemI2 -> OpCodes.Stelem_I2
            | StelemI4 -> OpCodes.Stelem_I4
            | StelemI8 -> OpCodes.Stelem_I8
            | StelemR4 -> OpCodes.Stelem_R4
            | StelemR8 -> OpCodes.Stelem_R8
            | StelemRef -> OpCodes.Stelem_Ref
            | Ldelem _ -> OpCodes.Ldelem
            | Stelem _ -> OpCodes.Stelem
            | UnboxAny _ -> OpCodes.Unbox_Any
            | ConvOvfI1 -> OpCodes.Conv_Ovf_I1
            | ConvOvfU1 -> OpCodes.Conv_Ovf_U1
            | ConvOvfI2 -> OpCodes.Conv_Ovf_I2
            | ConvOvfU2 -> OpCodes.Conv_Ovf_U2
            | ConvOvfI4 -> OpCodes.Conv_Ovf_I4
            | ConvOvfU4 -> OpCodes.Conv_Ovf_U4
            | ConvOvfI8 -> OpCodes.Conv_Ovf_I8
            | ConvOvfU8 -> OpCodes.Conv_Ovf_U8
            | Refanyval _ -> OpCodes.Refanyval
            | Ckfinite -> OpCodes.Ckfinite
            | Mkrefany _ -> OpCodes.Mkrefany
            | Ldtoken _ -> OpCodes.Ldtoken
            | ConvU2 -> OpCodes.Conv_U2
            | ConvU1 -> OpCodes.Conv_U1
            | ConvI -> OpCodes.Conv_I
            | ConvOvfI -> OpCodes.Conv_Ovf_I
            | ConvOvfU -> OpCodes.Conv_Ovf_U
            | AddOvf -> OpCodes.Add_Ovf
            | AddOvfUn -> OpCodes.Add_Ovf_Un
            | MulOvf -> OpCodes.Mul_Ovf
            | MulOvfUn -> OpCodes.Mul_Ovf_Un
            | SubOvf -> OpCodes.Sub_Ovf
            | SubOvfUn -> OpCodes.Sub_Ovf_Un
            | Endfinally -> OpCodes.Endfinally
            | Leave _ -> OpCodes.Leave
            | StindI _ -> OpCodes.Stind_I
            | ConvU -> OpCodes.Conv_U
            | Arglist -> OpCodes.Arglist
            | Ceq -> OpCodes.Ceq
            | Cgt -> OpCodes.Cgt
            | CgtUn -> OpCodes.Cgt_Un
            | Clt -> OpCodes.Clt
            | CltUn -> OpCodes.Clt_Un
            | Ldftn _ -> OpCodes.Ldftn
            | Ldvirtftn _ -> OpCodes.Ldvirtftn
            | Localloc -> OpCodes.Localloc
            | Endfilter -> OpCodes.Endfilter
            | Initobj _ -> OpCodes.Initobj
            | Cpblk _ -> OpCodes.Cpblk
            | Initblk _ -> OpCodes.Initblk
            | Rethrow -> OpCodes.Rethrow
            | Sizeof _ -> OpCodes.Sizeof
            | Refanytype -> OpCodes.Refanytype

        member x.StackBehaviourPop = x.ArchetypeOpCode.StackBehaviourPop
        member x.StackBehaviourPush = x.ArchetypeOpCode.StackBehaviourPush

        member x.PopTypes (stackTypes : list<#StackTyped>) =
            // TODO ARRG!! what about throw, rethrow, return ...
            match x with
            | Leave _ | Endfinally | Throw ->
                (stackTypes, [])
            | _ ->
                match x.StackBehaviourPop with
                | StackBehaviour.Pop0 ->
                    ([], stackTypes)
                | StackBehaviour.Pop1
                | StackBehaviour.Popi
                | StackBehaviour.Popref ->
                    match stackTypes with
                    | a :: stackTail -> ([a], stackTail)
                    | [] -> failwith "unexpected empty stack"
                | StackBehaviour.Pop1_pop1
                | StackBehaviour.Popi_pop1
                | StackBehaviour.Popi_popi
                | StackBehaviour.Popi_popi8
                | StackBehaviour.Popi_popr4
                | StackBehaviour.Popi_popr8
                | StackBehaviour.Popref_pop1
                | StackBehaviour.Popref_popi ->
                    match stackTypes with
                    | a :: b :: stackTail -> ([a; b], stackTail)
                    | _ -> failwith "expected at least two items in the stack"
                | StackBehaviour.Popi_popi_popi
                | StackBehaviour.Popref_popi_popi
                | StackBehaviour.Popref_popi_pop1
                | StackBehaviour.Popref_popi_popi8
                | StackBehaviour.Popref_popi_popr4
                | StackBehaviour.Popref_popi_popr8
                | StackBehaviour.Popref_popi_popref ->
                    match stackTypes with
                    | a :: b :: c :: stackTail -> ([a; b; c], stackTail)
                    | _ -> failwith "expected at least three items in the stack"
                | StackBehaviour.Varpop ->
                    let methSigPopCount (meth : Method) =
                        let methSig = meth.Signature
                        let paramLen = methSig.methParams.Length
                        match methSig.thisKind with
                        | ThisKind.HasThis ->
                            paramLen + 1
                        | ThisKind.ExplicitThis | ThisKind.NoThis ->
                            paramLen

                    let popCount =
                        match x with
                        | Call call | Calli call ->
                            methSigPopCount call.Method
                        | Callvirt virtCall ->
                            methSigPopCount virtCall.Method
                        | Newobj methRef ->
                            // TODO double check the - 1 here
                            methSigPopCount methRef - 1
                        | Ret ->
                            match stackTypes with
                            | [] -> 0
                            | [_] -> 1
                            | _ -> failwith "a ret instruction should only have 0 or 1 items on the stack"
                        | _ ->
                            failwithf "unexpected variable pop for instruction: %A" x

                    splitAt popCount stackTypes

                | popB ->
                    failwithf "unexpected pop behavior %A" popB

        /// update the type stack
        member x.TypesToPush (meth : MethodDef) (poppedTypes : list<#StackTyped>) =

            let poppedTypes = [for t in poppedTypes -> t.StackType]

            let badStack () = failwithf "bad stack types for %A found %A at the top of stack" x poppedTypes

            match x with
            | Add | Div | Mul | Rem | Sub ->

                // binary numeric operations defined in
                // Partition III 1.5
                // TODO: assuming valid bytecode here
                match poppedTypes with
                | [Int32_ST; Int32_ST] ->
                    Some [Int32_ST]
                | [Float32_ST; Float32_ST] ->
                    Some [Float32_ST]
                | [(Float64_ST | Float32_ST); (Float64_ST | Float32_ST)] ->
                    Some [Float64_ST]
                | [ManagedPointer_ST; ManagedPointer_ST] ->
                    Some [NativeInt_ST]
                | [_; ManagedPointer_ST] | [ManagedPointer_ST; _] ->
                    Some [ManagedPointer_ST]
                | [_; NativeInt_ST] | [NativeInt_ST; _] ->
                    Some [NativeInt_ST]
                | _ ->
                    badStack ()

            | Neg | Not ->
                Some poppedTypes

            // Binary Comparison or Branch Operations
            // Used for beq, beq.s, bge, bge.s, bge.un, bge.un.s, bgt, bgt.s,
            // bgt.un, bgt.un.s, ble, ble.s, ble.un, ble.un.s, blt, blt.s, blt.un,
            // blt.un.s, bne.un, bne.un.s, ceq, cgt, cgt.un, clt, clt.un
            | Beq _ | Bge _ | Bgt _ | Ble _ | Blt _
            | BneUn _ | BgeUn _ | BgtUn _ | BleUn _ | BltUn _ ->
                Some []
            | Ceq | Cgt | CgtUn | Clt | CltUn ->
                Some [Int32_ST]

            // The shl and shr instructions return the same type as their first operand
            // and their second operand shall be of type int32 or native int
            | Shl | Shr | ShrUn ->
                match poppedTypes with
                | [Int32_ST; fstOpType] | [NativeInt_ST; fstOpType] ->
                    Some [fstOpType]
                | _ ->
                    badStack ()

            // Integer Operations: Used for and, div.un, not, or, rem.un, xor
            // Note: I put Not with Neg above
            | And | DivUn | Or | RemUn | Xor ->
                match poppedTypes with
                | [Int32_ST; Int32_ST] ->
                    Some [Int32_ST]
                | [Int64_ST; Int64_ST] ->
                    Some [Int64_ST]
                | [NativeInt_ST; _] | [_; NativeInt_ST] ->
                    Some [NativeInt_ST]
                | _ ->
                    badStack ()

            // Overflow Arithmetic Operations: Used for add.ovf, add.ovf.un,
            // mul.ovf, mul.ovf.un, sub.ovf, and sub.ovf.un
            | AddOvf | AddOvfUn | MulOvf | MulOvfUn | SubOvf | SubOvfUn ->
                match poppedTypes with
                | [Int32_ST; Int32_ST] ->
                    Some [Int32_ST]
                | [Int64_ST; Int64_ST] ->
                    Some [Int64_ST]
                | [ManagedPointer_ST; ManagedPointer_ST] ->
                    Some [NativeInt_ST]
                | [_; ManagedPointer_ST] | [ManagedPointer_ST; _] ->
                    Some [ManagedPointer_ST]
                | [NativeInt_ST; _] | [_; NativeInt_ST] ->
                    Some [NativeInt_ST]
                | _ ->
                    badStack ()

            // data conversion
            | ConvI1 | ConvI2 | ConvI4 | ConvU4 | ConvU2 | ConvU1
            | ConvOvfI1 | ConvOvfU1 | ConvOvfI2 | ConvOvfU2 | ConvOvfI4 | ConvOvfU4
            | ConvOvfI1Un | ConvOvfI2Un | ConvOvfI4Un | ConvOvfU1Un | ConvOvfU2Un | ConvOvfU4Un ->
                Some [Int32_ST]
            | ConvI8 | ConvU8 | ConvOvfI8Un | ConvOvfU8Un | ConvOvfI8 | ConvOvfU8 ->
                Some [Int64_ST]
            | ConvR4 ->
                Some [Float32_ST]
            | ConvR8 | ConvRUn ->
                // TODO is it OK to use float64 for conv.r.un? I'm guessing so.
                Some [Float64_ST]
            | ConvI | ConvU | ConvOvfIUn | ConvOvfUUn | ConvOvfI | ConvOvfU ->
                Some [NativeInt_ST]

            | Brfalse _ | Brtrue _ ->
                match poppedTypes with
                | [_] -> Some []
                | _ -> badStack ()

            | Br _ ->
                match poppedTypes with
                | [] -> Some []
                | _ -> badStack ()

            | LdindI1 _ | LdindU1 _ | LdindI2 _ | LdindU2 _ | LdindI4 _ | LdindU4 _ ->
                match poppedTypes with
                | [NativeInt_ST] | [ManagedPointer_ST] -> Some [Int32_ST]
                | _ -> badStack ()
            | LdindI8 _ ->
                match poppedTypes with
                | [NativeInt_ST] | [ManagedPointer_ST] -> Some [Int64_ST]
                | _ -> badStack ()
            | LdindI _ ->
                match poppedTypes with
                | [NativeInt_ST] | [ManagedPointer_ST] -> Some [NativeInt_ST]
                | _ -> badStack ()
            | LdindR4 _ ->
                match poppedTypes with
                | [NativeInt_ST] | [ManagedPointer_ST] -> Some [Float32_ST]
                | _ -> badStack ()
            | LdindR8 _ ->
                match poppedTypes with
                | [NativeInt_ST] | [ManagedPointer_ST] -> Some [Float64_ST]
                | _ -> badStack ()
            | LdindRef _ ->
                match poppedTypes with
                | [NativeInt_ST] | [ManagedPointer_ST] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Break | Nop ->
                match poppedTypes with
                | [] -> Some []
                | _ -> badStack ()

            | LdcI4 _ ->
                match poppedTypes with
                | [] -> Some [Int32_ST]
                | _ -> badStack ()
            | LdcI8 _ ->
                match poppedTypes with
                | [] -> Some [Int64_ST]
                | _ -> badStack ()
            | LdcR4 _ ->
                match poppedTypes with
                | [] -> Some [Float32_ST]
                | _ -> badStack ()
            | LdcR8 _ ->
                match poppedTypes with
                | [] -> Some [Float64_ST]
                | _ -> badStack ()

            | LdelemI1 | LdelemU1 | LdelemI2 | LdelemU2 | LdelemI4 | LdelemU4 ->
                Some [Int32_ST]
            | LdelemI8 ->
                Some [Int64_ST]
            | LdelemI ->
                Some [NativeInt_ST]
            | LdelemR4 ->
                Some [Float32_ST]
            | LdelemR8 ->
                Some [Float64_ST]
            | LdelemRef ->
                Some [ObjectRef_ST]

            | StelemI | StelemI1 | StelemI2 | StelemI4
            | StelemI8 | StelemR4 | StelemR8 | StelemRef | Stelem _ ->
                match poppedTypes with
                | [_; Int32_ST; ObjectRef_ST]
                | [_; NativeInt_ST; ObjectRef_ST] ->
                    Some []
                | _ ->
                    badStack ()

            | StindRef _ | StindI1 _ | StindI2 _ | StindI4 _
            | StindI8 _ | StindR4 _ | StindR8 _ | StindI _ ->
                Some []

            | Dup ->
                match poppedTypes with
                | [item] -> Some [item; item]
                | _ -> badStack ()

            | Ldnull | Ldstr _ ->
                match poppedTypes with
                | [] -> Some [ObjectRef_ST]
                | _ -> badStack ()
        
            | Starg _ | Stloc _ | Stsfld _ ->
                match poppedTypes with
                | [_] -> Some []
                | _ -> badStack ()
        
            | Stfld _ ->
                match poppedTypes with
                | [_; (ObjectRef_ST | NativeInt_ST | ManagedPointer_ST)] -> Some []
                | _ -> badStack ()
        
            | Stobj _ ->
                match poppedTypes with
                | [_; _] -> Some []
                | _ -> badStack ()

            | Ldlen ->
                match poppedTypes with
                | [ObjectRef_ST] -> Some [NativeInt_ST]
                | _ -> badStack ()

            | Pop ->
                match poppedTypes with
                | [_] -> Some []
                | _ -> badStack ()

            | Newarr _ ->
                match poppedTypes with
                | [Int32_ST] | [NativeInt_ST] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Box _ ->
                match poppedTypes with
                | [_] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Throw ->
                match poppedTypes with
                | [ObjectRef_ST] -> None
                | _ -> badStack ()
        
            | Jmp _ ->
                match poppedTypes with
                | [] -> None
                | _ -> badStack ()

            | Ret ->
                match poppedTypes with
                | [] | [_] -> None
                | _ -> badStack ()

            | Leave _ -> None

            | Ckfinite -> Some poppedTypes

            | Endfinally -> None
        
            | Ldftn _ -> Some [NativeInt_ST]

            | Call call | Calli call ->
                let retTy = call.Method.Signature.retType
                match retTy.rType with
                | RetTypeKind.Void -> Some []
                | _ -> Some [retTy.AsIntermediateType()]

            | Callvirt virtCall ->
                let retTy = virtCall.Method.Signature.retType
                match retTy.rType with
                | RetTypeKind.Void -> Some []
                | _ -> Some [retTy.AsIntermediateType()]

            | Newobj methodRef ->
                let decTy = methodRef.Resolve().DeclaringType
                Some [decTy.AsIntermediateType()]

            | Cpobj _ ->
                match poppedTypes with
                | [(NativeInt_ST | ManagedPointer_ST); (NativeInt_ST | ManagedPointer_ST)] ->
                    None
                | _ ->
                    badStack ()

            | Ldarga _ | Ldloca _ ->
                Some [ManagedPointer_ST]
        
            | Ldflda _ ->
                match poppedTypes with
                | [(ObjectRef_ST | ManagedPointer_ST)] ->
                    Some [ManagedPointer_ST]
                | [NativeInt_ST] ->
                    Some [NativeInt_ST]
                | _ ->
                    badStack ()

            | Ldelema _ ->
                match poppedTypes with
                | [(Int32_ST | NativeInt_ST); ObjectRef_ST] ->
                    Some [ManagedPointer_ST]
                | _ ->
                    badStack ()

            | Ldelem ty ->
                match poppedTypes with
                | [(Int32_ST | NativeInt_ST); ObjectRef_ST] ->
                    Some [ty.AsIntermediateType()]
                | _ ->
                    badStack ()

            | Ldarg i ->
                match poppedTypes with
                | [] ->
                    let param = meth.AllParameters.[int i]
                    Some [param.Type.AsIntermediateType()]
                | _ -> badStack ()

            | Ldloc i ->
                match poppedTypes with
                | [] ->
                    let local = meth.Locals.[int i]
                    Some [local.AsIntermediateType()]
                | _ -> badStack ()

        
            | Ldobj (_, _, ty) ->
                match poppedTypes with
                | [NativeInt_ST | ManagedPointer_ST] ->
                    Some [ty.AsIntermediateType()]
                | _ -> badStack ()

            | Switch _ ->
                Some []

            | Isinst _ | Castclass _ ->
                match poppedTypes with
                | [ObjectRef_ST] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Ldfld (_, _, field) ->
                match poppedTypes with
                | [ObjectRef_ST | ManagedPointer_ST | NativeInt_ST] ->
                    Some [field.Signature.fType.AsIntermediateType()]
                | _ ->
                    badStack ()

            | Ldsfld (_, field) ->
                match poppedTypes with
                | [] -> Some [field.Signature.fType.AsIntermediateType()]
                | _ -> badStack ()

            | Unbox ty ->
                match poppedTypes with
                | [ObjectRef_ST] -> Some [ty.AsIntermediateType()]
                | _ -> badStack ()

            | UnboxAny ty ->
                match poppedTypes with
                | [ObjectRef_ST] -> Some [ty.AsIntermediateType()]
                | _ -> badStack ()

            | Mkrefany _ ->
                match poppedTypes with
                | [ManagedPointer_ST | NativeInt_ST] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Refanyval ty ->
                // Correct CIL ensures that typedRef is a valid typed reference (created by a previous call to mkrefany).
                match poppedTypes with
                | [ObjectRef_ST] -> Some [ManagedPointer_ST]
                | _ -> badStack ()

            | Refanytype ->
                match poppedTypes with
                | [ObjectRef_ST] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Ldtoken _ ->
                match poppedTypes with
                | [] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Arglist ->
                match poppedTypes with
                | [] -> Some [ObjectRef_ST]
                | _ -> badStack ()

            | Ldvirtftn _ ->
                match poppedTypes with
                | [ObjectRef_ST] -> Some [NativeInt_ST]
                | _ -> badStack ()
            
            | Localloc ->
                // TODO verify: correct CIL requires that the evaluation stack be
                // empty, apart from the size item
                match poppedTypes with
                | [NativeInt_ST | Int32_ST] -> Some [NativeInt_ST]
                | _ -> badStack ()

            | Endfilter ->
                match poppedTypes with
                | [Int32_ST] -> Some []
                | _ -> badStack ()

            | Initobj _ ->
                match poppedTypes with
                | [ManagedPointer_ST | NativeInt_ST] -> Some []
                | _ -> badStack ()

            | Cpblk _ | Initblk _ ->
                match poppedTypes with
                | [Int32_ST; (ManagedPointer_ST | NativeInt_ST); (ManagedPointer_ST | NativeInt_ST)] ->
                    Some []
                | _ ->
                    badStack ()

            | Rethrow ->
                match poppedTypes with
                | [] -> Some []
                | _ -> badStack ()

            | Sizeof _ ->
                match poppedTypes with
                | [] -> Some [Int32_ST]
                | _ -> badStack ()

            | Ldsflda (_, field) ->
                match poppedTypes with
                | [] ->
                    match field.Resolve().FieldRVA with
                    | None -> Some [ManagedPointer_ST]
                    | Some _ -> Some [NativeInt_ST]
                | _ ->
                    badStack ()

//
// BLOB PARSING
//

and SpecifiedLocalVar = {
    pinned : bool
    custMods : CustomModBlob array
    mayByRefType : MaybeByRefType
}
and LocalVarSig =
    | SpecifiedType of SpecifiedLocalVar
    | TypedByRef
    with
        member x.AsIntermediateType() =
            match x with
            | TypedByRef -> failwithf "intermediate type not supported for %A" x
            | SpecifiedType specLocalVar ->
                specLocalVar.mayByRefType.AsIntermediateType()

        static member FromBlob (assem : Assembly) (blob : byte list ref) =
            let unexpEnd() = failwith "unexpected end of blob while reading LocalVarSig"
            match listRead blob with
            | Some 0x07uy ->
                let readByteFun = makeReadByteFun blob
                let count = readCompressedUnsignedInt readByteFun
                
                [|for _ in 1u .. count do
                    yield
                        match !blob with
                        | [] -> unexpEnd()
                        | ElTy ElementType.TypedByRef :: _ ->
                            listSkip blob
                            LocalVarSig.TypedByRef
                        | _ ->
                            let isPinned = ref false
                            let custMods = [|
                                let notDone = ref true
                                while !notDone do
                                    match !blob with
                                    | [] -> unexpEnd()
                                    | ElTy ElementType.Pinned :: _ ->
                                        if !isPinned then failwith "field set to pinned twice"
                                        listSkip blob
                                        isPinned := true
                                    | ElTy (ElementType.CmodOpt | ElementType.CmodReqd) :: _ ->
                                        yield CustomModBlob.FromBlob assem blob
                                    | _ -> notDone := false
                            |]
                            let maybeByRefTy = MaybeByRefType.FromBlob assem blob
                            let specTy = {
                                SpecifiedLocalVar.pinned = !isPinned
                                custMods = custMods
                                mayByRefType = maybeByRefTy
                            }
                            LocalVarSig.SpecifiedType specTy|]

            | Some b -> failwithf "expected LocalVarSig to start with 0x07 but observed 0x%X" b
            | None -> unexpEnd()

and TryAndHandler = {
    tryOffsetLen : uint32 * uint32
    handlerOffsetLen : uint32 * uint32}

and ExceptionClause =
    | TypedException of TryAndHandler * MetadataToken
    | Finally of TryAndHandler * MetadataToken // TODO do we really need MetadataToken here?
    | Fault of TryAndHandler * MetadataToken // TODO do we really need MetadataToken here?

    // Section 12.4.2.7: If an exception entry contains a filterstart, then
    // filterstart strictly precedes handlerstart. The filter starts at the
    // instruction specified by filterstart and contains all instructions up to
    // (but not including) that specified by handlerstart. The lexically last
    // instruction in the filter must be endfilter. If there is no filterstart
    // then the filter is empty (hence it does not overlap with any region).
    | Filter of TryAndHandler * uint32
    with
        static member private ToExceptionClause
                (eFlags : uint32)
                (tryOffset : uint32)
                (tryLen : uint32)
                (handlerOffset : uint32)
                (handlerLen : uint32)
                (offsetOrClassTok : uint32) =

            let tryAndHdlr = {
                tryOffsetLen = tryOffset, tryLen
                handlerOffsetLen = handlerOffset, handlerLen}
            match eFlags with
            | 0x0000u -> TypedException (tryAndHdlr, toMetadataToken offsetOrClassTok)
            | 0x0001u -> Filter (tryAndHdlr, offsetOrClassTok)
            | 0x0002u -> Finally (tryAndHdlr, toMetadataToken offsetOrClassTok)
            | 0x0004u -> Fault (tryAndHdlr, toMetadataToken offsetOrClassTok)
            | _ -> failwithf "bad exception clause kind 0x%X" eFlags

        static member private ReadFatExceptionClauses (r : BinaryReader) =
            // Section 25.4.3
            let dataSize =
                match r.ReadBytes 3 with
                | [|b1; b2; b3|] ->
                    // these are little-endian, so little bytes first
                    uint32 b1 ||| (uint32 b2 <<< 8) ||| (uint32 b3 <<< 16)
                | _ ->
                    failwith "unexpected end of file while reading data section"
            let numClauses = (dataSize - 4u) / 24u

            if (numClauses * 24u) + 4u <> dataSize then
                failwithf "bad dataSize in fat section: %i" dataSize
    
            // See 25.4.6 reading fat clauses
            [|for _ in 1u .. numClauses ->
                //debugfn "reading fat clause"
                let eFlags = r.ReadUInt32 ()
                let tryOffset = r.ReadUInt32 ()
                let tryLen = r.ReadUInt32 ()
                let handlerOffset = r.ReadUInt32 ()
                let handlerLen = r.ReadUInt32 ()
                let offsetOrClassTok = r.ReadUInt32 ()

                (*debugfn
                    "eFlags=0x%X, tryOffset=%i, tryLen=%i, handlerOffset=%i, handlerLen=%i, offsetOrClassTok=%i"
                    eFlags
                    tryOffset
                    tryLen
                    handlerOffset
                    handlerLen
                    offsetOrClassTok*)

                ExceptionClause.ToExceptionClause
                    eFlags
                    tryOffset
                    tryLen
                    handlerOffset
                    handlerLen
                    offsetOrClassTok|]

        static member private ReadSmallExceptionClauses (r : BinaryReader) =
            // Section 25.4.2
            let dataSize = r.ReadByte ()
            let numClauses = (dataSize - 4uy) / 12uy
            readShortEq r 0us "small method header reserved"
    
            if (numClauses * 12uy) + 4uy <> dataSize then
                failwithf "bad dataSize in small section: %i" dataSize
    
            // See 25.4.6 reading small clauses
            [|for _ in 1uy .. numClauses ->
                //debugfn "reading small clause"
                let eFlags = r.ReadUInt16 () |> uint32
                let tryOffset = r.ReadUInt16 () |> uint32
                let tryLen = r.ReadByte () |> uint32
                let handlerOffset = r.ReadUInt16 () |> uint32
                let handlerLen = r.ReadByte () |> uint32
                let offsetOrClassTok = r.ReadUInt32 ()

                (*debugfn
                    "eFlags=0x%X, tryOffset=%i, tryLen=%i, handlerOffset=%i, handlerLen=%i, offsetOrClassTok=%i"
                    eFlags
                    tryOffset
                    tryLen
                    handlerOffset
                    handlerLen
                    offsetOrClassTok*)

                ExceptionClause.ToExceptionClause
                    eFlags
                    tryOffset
                    tryLen
                    handlerOffset
                    handlerLen
                    offsetOrClassTok|]

        static member ReadExceptionSections (r : BinaryReader) (moreSects : bool) (codeSize : uint32) =
            let moreSects = ref moreSects
            [|while !moreSects do
                //debugfn "reading exception section"
        
                // the method data sits on a 4-byte boundary. Seek past
                // boundary bytes
                let codeRem = codeSize % 4u
                if codeRem <> 0u then
                    let seekDist = 4L - int64 codeRem
                    r.BaseStream.Seek (seekDist, SeekOrigin.Current) |> ignore

                let kindFlags = r.ReadByte ()
                let isException = kindFlags &&& 0x01uy <> 0uy
                if not isException then
                    failwith "expected exception flag to be set"
                let optILTable = kindFlags &&& 0x02uy <> 0uy
                if optILTable then
                    failwith "expected optILTable flag to be unset"
                let isFatFormat = kindFlags &&& 0x40uy <> 0uy
                moreSects := kindFlags &&& 0x80uy <> 0uy

                //debugfn "exception is fat: %b" isFatFormat

                yield
                    if isFatFormat then
                        ExceptionClause.ReadFatExceptionClauses r
                    else
                        ExceptionClause.ReadSmallExceptionClauses r|]

and [<RequireQualifiedAccess>] CustomModBlob = {
    isRequired : bool
    theType : TypeDefRefOrSpec
}
with
    member x.CilId(assemCtxt:AssemblyBase) =
        let reqStr =
            if x.isRequired then
                "modreq"
            else
                "modopt"
        match x.theType with
        | :? TypeDefOrRef as ty ->
            sprintf "%s (%s)" reqStr (ty.CilId(false, assemCtxt))
        | ty ->
            failwith "TODO: custom mod of %A" ty

    static member FromBlob (assem : Assembly) (blob : byte list ref) =
        match listRead blob with
        | None -> failwith "unexpected end of blob while reading custom mod"
        | Some b ->
            let isReq =
                match enum<ElementType>(int b) with
                | ElementType.CmodOpt -> false
                | ElementType.CmodReqd -> true
                | et -> failwithf "unexpected element type while reading custom mod: %A" et

            {
                CustomModBlob.isRequired = isReq
                theType = TypeDefRefOrSpec.FromBlob assem blob
            }

    static member ManyFromBlob (assem : Assembly) (blob : byte list ref) =
        let notEndOfCustMods (b : byte) =
            b = byte ElementType.CmodOpt || b = byte ElementType.CmodReqd
        readBlobWhile notEndOfCustMods (CustomModBlob.FromBlob assem) blob

// defined at Partition II: 23.2.12
and [<RequireQualifiedAccess>] TypeBlob =
    | Boolean | Char | I1 | U1 | I2 | U2 | I4 | U4 | I8 | U8 | R4 | R8 | I | U
    | Class of TypeDefRefOrSpec
    | MVar of uint32
    | Object
    | String
    | ValueType of TypeDefRefOrSpec
    | Var of uint32

    // the following are also in type spec
    | Ptr of List<CustomModBlob> * Option<TypeBlob>
    | FnPtr of MethodDefOrRefSig
    | Array of TypeBlob * ArrayShape
    | SzArray of List<CustomModBlob> * TypeBlob
    // GenericInst bool isClass with false indicating valuetype
    | GenericInst of GenericTypeInst
    with
        /// see Partition I: 8.7
        member x.AsIntermediateType() : StackType =
    
            let iHaveNoClue () =
                failwithf "I have no clue what to do with %A" x
    
            let fromManagedPtr (pointeeType : TypeBlob) =
                match pointeeType with
                | Boolean | Char | I1 | U1 | I2 | U2 | I4 | U4 -> iHaveNoClue() //Int32_ST
                | I8 | U8 -> iHaveNoClue() //Int64_ST
                | R4 -> iHaveNoClue() //Float32_ST
                | R8 -> iHaveNoClue() //Float64_ST
                | I | U -> iHaveNoClue() //NativeInt_ST
                | _ -> ManagedPointer_ST

            match x with
            | Ptr (custMods, tyOpt) ->
                match tyOpt with
                | None ->
                    // None corresponds to a void* as in: ldfld void* System.IntPtr::m_value
                    NativeInt_ST
                | Some ty -> fromManagedPtr ty
            | Boolean | Char | I1 | U1 | I2 | U2 | I4 | U4 -> Int32_ST
            | I8 | U8 -> Int64_ST
            | R4 -> Float32_ST
            | R8 -> Float64_ST
            | I | U -> NativeInt_ST
            | Object | String -> ObjectRef_ST
            | ValueType _ ->
                // TODO I think this is probably completely bogus
                ObjectRef_ST
            | Class _ ->
                // TODO understand difference between object and class
                // I think Object means the base object type
                ObjectRef_ST
            | Var _ -> iHaveNoClue ()
            | Array _ | SzArray _ -> ObjectRef_ST
            | GenericInst _ -> iHaveNoClue ()
            | FnPtr _ -> iHaveNoClue ()
            | MVar _ -> iHaveNoClue ()

        static member PtrTo (ty:TypeBlob) : TypeBlob = Ptr([], Some ty)
        static member SzArrayOf (ty:TypeBlob) : TypeBlob = SzArray([], ty)

        static member TypesMatch (ty1 : TypeBlob) (ty2 : TypeBlob) : bool =
            match ty1, ty2 with
            | TypeBlob.Class ty1, TypeBlob.Class ty2
            | TypeBlob.ValueType ty1, TypeBlob.ValueType ty2 ->
                TypeDefRefOrSpec.SameType ty1 ty2

            | TypeBlob.Array (ty1, _), TypeBlob.Array (ty2, _)
            | TypeBlob.SzArray (_, ty1), TypeBlob.SzArray (_, ty2) ->
                // TODO do we need to worry about array shapes or custom mods here?
                TypeBlob.TypesMatch ty1 ty2

            | TypeBlob.GenericInst gt1, TypeBlob.GenericInst gt2 ->
                GenericTypeInst.TypesMatch gt1 gt2

            | TypeBlob.Ptr _, TypeBlob.Ptr _
            | TypeBlob.FnPtr _, TypeBlob.FnPtr _ ->
                failwithf "TODO implement TypesMatch for %A %A" ty1 ty2
            | _ ->
                // we can fall back on structural equality for everything else
                ty1 = ty2

        member x.CilId(assemCtxt:AssemblyBase) =
            match x with
            | TypeBlob.Boolean -> "bool"
            | TypeBlob.Char -> "char"
            | TypeBlob.I1 -> "int8"
            | TypeBlob.U1 -> "unsigned int8"
            | TypeBlob.I2 -> "int16"
            | TypeBlob.U2 -> "unsigned int16"
            | TypeBlob.I4 -> "int32"
            | TypeBlob.U4 -> "unsigned int32"
            | TypeBlob.I8 -> "int64"
            | TypeBlob.U8 -> "unsigned int64"
            | TypeBlob.R4 -> "float32"
            | TypeBlob.R8 -> "float64"
            | TypeBlob.I -> "native int"
            | TypeBlob.U -> "native unsigned int"
            | TypeBlob.Class (:? TypeDefOrRef as tyDefOrRef) -> "class " + tyDefOrRef.CilId(false, assemCtxt)
            | TypeBlob.Class _ -> failwithf "TODO can't turn %A into string" x
            | TypeBlob.MVar i -> "!!" + string i
            | TypeBlob.Object -> "object"
            | TypeBlob.String -> "string"
            | TypeBlob.ValueType (:? TypeDefOrRef as tyDefOrRef) -> "valuetype " + tyDefOrRef.CilId(false, assemCtxt)
            | TypeBlob.ValueType _ -> failwithf "TODO can't turn %A into string" x
            | TypeBlob.Var i -> "!" + string i

            // the following are also in type spec
            | TypeBlob.Ptr (custMods, tyOpt) ->
                spaceSepStrs [|
                    match tyOpt with
                    | None      -> yield "void*"
                    | Some ty   -> yield ty.CilId(assemCtxt) + "*"

                    for cm in custMods do
                        yield cm.CilId(assemCtxt)
                |]

            | TypeBlob.FnPtr methDefOrRef ->
                spaceSepStrs [|
                    yield "method"

                    match methDefOrRef.thisKind with
                    | ThisKind.NoThis -> ()
                    | ThisKind.ExplicitThis -> yield! [|"instance"; "explicit"|]
                    | ThisKind.HasThis -> yield "instance"

                    yield "*"
                    yield "(TODO_PARAMS_GO_HERE)"
                |]
            | TypeBlob.Array (tyBlob, arrShape) ->
                tyBlob.CilId(assemCtxt) + "[" + arrShape.ToString() + "]"
            | TypeBlob.SzArray (custMods, tyBlob) ->
                spaceSepStrs [|
                    yield tyBlob.CilId(assemCtxt) + "[]"
                    for cm in custMods do
                        yield cm.CilId(assemCtxt)
                |]
            // GenericInst bool isClass with false indicating valuetype
            | TypeBlob.GenericInst genTyInst ->
                spaceSepStrs [|
                    "TODO_GENERIC_INST"
                |]

        member x.SizeBytes =
            match x with
            | TypeBlob.Boolean | TypeBlob.U1 | TypeBlob.I1 ->
                Some 1
            | TypeBlob.U2 | TypeBlob.I2 | TypeBlob.Char ->
                Some 2
            | TypeBlob.U4 | TypeBlob.I4 | TypeBlob.R4 ->
                Some 4
            | TypeBlob.U8 | TypeBlob.I8 | TypeBlob.R8 ->
                Some 8
            | TypeBlob.Ptr _ | TypeBlob.FnPtr _ | TypeBlob.I ->
                Some System.IntPtr.Size
            | TypeBlob.ValueType ty ->
                ty.SizeBytes
            | _ ->
                None

        member x.IsPrimitive =
            match x with
            | Boolean | Char | I1 | U1 | I2 | U2 | I4 | U4 | I8 | U8 | R4 | R8 | I | U ->
                true
            | _ ->
                // TODO what about Ptr and FnPtr? What about when generic types take on primitives?
                false

        member x.IsValType =
            if x.IsPrimitive then
                true
            else
                match x with
                | ValueType _ -> true
                | _ -> false

        static member FromBlob (assem : Assembly) (blob : byte list ref) : TypeBlob =
            match !blob with
            | [] -> failwith "unexpected end of blob while reading type"
            | b :: _ ->
                //let readUInt() = readCompressedUnsignedInt (makeReadByteFun blob)
                match enum<ElementType>(int b) with
                | ElementType.Boolean       -> listSkip blob; Boolean
                | ElementType.Char          -> listSkip blob; Char
                | ElementType.I1            -> listSkip blob; I1
                | ElementType.U1            -> listSkip blob; U1
                | ElementType.I2            -> listSkip blob; I2
                | ElementType.U2            -> listSkip blob; U2
                | ElementType.I4            -> listSkip blob; I4
                | ElementType.U4            -> listSkip blob; U4
                | ElementType.I8            -> listSkip blob; I8
                | ElementType.U8            -> listSkip blob; U8
                | ElementType.R4            -> listSkip blob; R4
                | ElementType.R8            -> listSkip blob; R8
                | ElementType.I             -> listSkip blob; I
                | ElementType.U             -> listSkip blob; U
                | ElementType.Class         -> listSkip blob; Class(TypeDefRefOrSpec.FromBlob assem blob)
                //| ElementType.MVar          -> listSkip blob; MVar(readUInt())
                | ElementType.Object        -> listSkip blob; Object
                | ElementType.String        -> listSkip blob; String
                | ElementType.ValueType     -> listSkip blob; ValueType(TypeDefRefOrSpec.FromBlob assem blob)
                //| ElementType.Var           -> listSkip blob; Var(readUInt())

                // reuse the type-spec
                | _ ->
                    match TypeSpecBlob.FromBlob assem blob with
                    | TypeSpecBlob.Ptr(custMods, typeOption)    -> Ptr(custMods, typeOption)
                    | TypeSpecBlob.FnPtr methDefOrRef           -> FnPtr methDefOrRef
                    | TypeSpecBlob.Array(ty, shape)             -> Array(ty, shape)
                    | TypeSpecBlob.SzArray(custMods, types)     -> SzArray(custMods, types)
                    | TypeSpecBlob.MVar i                       -> MVar i
                    | TypeSpecBlob.Var i                        -> Var i
                    | TypeSpecBlob.GenericInst genTyInst        -> GenericInst genTyInst

and MaybeByRefType = {isByRef : bool; ty : TypeBlob}
with
    /// see Partition I: 8.7
    member x.AsIntermediateType() =
        if x.isByRef then
            ManagedPointer_ST
        else
            x.ty.AsIntermediateType()

    static member FromBlob (assem : Assembly) (blob : byte list ref) =
        match !blob with
        | [] -> failwith "unexpected end of blob while reading MaybeByRefType"
        | b :: _ ->
            let isByRef =
                match enum<ElementType>(int b) with
                | ElementType.ByRef -> listSkip blob; true
                | _ -> false
            {MaybeByRefType.isByRef = isByRef; ty = TypeBlob.FromBlob assem blob}

and PropertySig = {
    hasThis : bool
    custMods : CustomModBlob list
    propType : TypeBlob
    indexParams : Param list
}
with
    static member FromBlob (assem : Assembly) (blob : byte list ref) : PropertySig =
        let hasThis =
            match listRead blob with
            | Some 0x08uy -> false
            | Some 0x28uy -> true
            | a -> failwithf "unexpected value while reading property sig: %A" a
        let paramCount = readCompressedUnsignedInt (makeReadByteFun blob)
        let custMods = CustomModBlob.ManyFromBlob assem blob
        let propType = TypeBlob.FromBlob assem blob

        {
            PropertySig.hasThis = hasThis
            custMods = custMods
            propType = propType
            indexParams = [for _ in 1u .. paramCount -> Param.FromBlob assem blob]
        }

and ThisKind = NoThis | HasThis | ExplicitThis
and [<RequireQualifiedAccess>] MethCallingConv = Default | Vararg | Generic of uint32
and MethodDefOrRefSig = {
    thisKind : ThisKind
    callingConv : MethCallingConv
    retType : RetType
    methParams : Param list
    varargParams : Param list
}
with
    static member FromBlob (assem : Assembly) (blob : byte list ref) : MethodDefOrRefSig =
        let unexpEnd() = failwith "unexpected end of blob while reading method def or ref sig"
        match listRead blob with
        | None -> unexpEnd()
        | Some b ->
            let bitsSet (mask : byte) = b &&& mask = mask
            let thisKind =
                let hasThis = bitsSet 0x20uy
                if hasThis then
                    let explicitThis = bitsSet 0x40uy
                    if explicitThis then ThisKind.ExplicitThis else ThisKind.HasThis
                else
                    NoThis
            let callingConv =
                let isVararg = bitsSet 0x5uy
                let isGeneric = bitsSet 0x10uy
                if isVararg then
                    MethCallingConv.Vararg
                elif isGeneric then
                    MethCallingConv.Generic(readCompressedUnsignedInt <| makeReadByteFun blob)
                else
                    MethCallingConv.Default
            let paramsRemaining = ref (readCompressedUnsignedInt (makeReadByteFun blob))
            let retType = RetType.FromBlob assem blob
            let methParams = [
                let hitSentinal = ref false
                while not !hitSentinal && !paramsRemaining >= 1u do
                    match !blob with
                    | ElTy ElementType.Sentinel :: _ ->
                        listSkip blob
                        hitSentinal := true
                    | _ ->
                        yield Param.FromBlob assem blob
                        paramsRemaining := !paramsRemaining - 1u
            ]
            let varargParams = [
                while !paramsRemaining >= 1u do
                    yield Param.FromBlob assem blob
                    paramsRemaining := !paramsRemaining - 1u
            ]

            {
                MethodDefOrRefSig.thisKind = thisKind
                callingConv = callingConv
                retType = retType
                methParams = methParams
                varargParams = varargParams
            }

and FieldSig = {
    customMods : CustomModBlob list
    fType : TypeBlob
}
with
    static member FromBlob (assem : Assembly) (blob : byte list ref) : FieldSig =
        match listRead blob with
        | Some 0x6uy ->
            let custMods = CustomModBlob.ManyFromBlob assem blob
            let ty = TypeBlob.FromBlob assem blob
            {
                FieldSig.customMods = custMods
                fType = ty
            }
        | Some et -> failwithf "the following element type is not valid for a field sig: %A" et
        | None -> failwith "unexpected end of blob while reading method def or ref sig"

    member x.CilId(assemCtxt:AssemblyBase) =
        if x.customMods.Length >= 1 then
            failwith "TODO need to deal with custmods in return type"
        x.fType.CilId(assemCtxt)

and [<RequireQualifiedAccess>] ParamType =
    | MayByRefTy of MaybeByRefType
    | TypedByRef
    with
        member x.CilId(assemCtxt:AssemblyBase) =
            match x with
            | ParamType.MayByRefTy mayByTyRef ->
                if mayByTyRef.isByRef then
                    mayByTyRef.ty.CilId(assemCtxt) + "&"
                else
                    mayByTyRef.ty.CilId(assemCtxt)
            | ParamType.TypedByRef ->
                failwith "TODO no can do for typedbyref"

and Param = {
    customMods : CustomModBlob list
    pType : ParamType
}
with
    /// see Partition I: 8.7
    member x.AsIntermediateType() =
        match x.pType with
        | ParamType.MayByRefTy mayByRef -> mayByRef.AsIntermediateType()
        | ParamType.TypedByRef -> failwith "TODO TypedByRef doesn't work for AsIntermediateType"

    static member FromBlob (assem : Assembly) (blob : byte list ref) : Param =
        let custMods = CustomModBlob.ManyFromBlob assem blob
        match !blob with
        | [] -> failwith "unexpected end of blob while reading ParamType"
        | b :: _ ->
            let pType =
                match enum<ElementType>(int b) with
                | ElementType.TypedByRef -> listSkip blob; ParamType.TypedByRef
                | _ -> ParamType.MayByRefTy (MaybeByRefType.FromBlob assem blob)
            {Param.customMods = custMods; pType = pType}

    static member ParamsMatch (p1 : Param) (p2 : Param) =
        // TODO do the customMods matter?
        match p1.pType, p2.pType with
        | ParamType.TypedByRef, ParamType.TypedByRef -> true
        | ParamType.MayByRefTy mayByRefTy1, ParamType.MayByRefTy mayByRefTy2 ->
            TypeBlob.TypesMatch mayByRefTy1.ty mayByRefTy2.ty
        | _ -> false

and [<RequireQualifiedAccess>] RetTypeKind =
    | MayByRefTy of MaybeByRefType
    | TypedByRef
    | Void
and RetType = {
    customMods : CustomModBlob list
    rType : RetTypeKind
}
with
    /// see Partition I: 8.7
    member x.AsIntermediateType() : StackType =
        match x.rType with
        | RetTypeKind.MayByRefTy mayByRef -> mayByRef.AsIntermediateType()
        | RetTypeKind.TypedByRef -> failwith "TODO TypedByRef doesn't work for AsIntermediateType"
        | RetTypeKind.Void -> failwith "TODO TypedByRef doesn't work for Void"

    member x.CilId(assemCtxt:AssemblyBase) =
        if x.customMods.Length >= 1 then
            failwith "TODO need to deal with custmods in return type"
        match x.rType with
        | RetTypeKind.Void -> "void"
        | RetTypeKind.TypedByRef -> failwith "TODO deal with typed by ref return type"
        | RetTypeKind.MayByRefTy mayByRefTy ->
            if mayByRefTy.isByRef then
                failwith "TODO not yet dealing with by ref return type"
            mayByRefTy.ty.CilId(assemCtxt)

    member x.IsVoid =
        match x.rType with
        | RetTypeKind.Void -> true
        | _ -> false

    static member FromBlob (assem : Assembly) (blob : byte list ref) : RetType =
        let custMods = CustomModBlob.ManyFromBlob assem blob
        match !blob with
        | [] -> failwith "unexpected end of blob while reading RetType"
        | b :: _ ->
            let rType =
                match enum<ElementType>(int b) with
                | ElementType.TypedByRef -> listSkip blob; RetTypeKind.TypedByRef
                | ElementType.Void -> listSkip blob; RetTypeKind.Void
                | _ -> RetTypeKind.MayByRefTy (MaybeByRefType.FromBlob assem blob)
            {RetType.customMods = custMods; rType = rType}

and ArrayShape = {rank : uint32; sizes : uint32 array; loBounds : int array}
with
    override x.ToString() =
        commaSepStrs [|
            for i = 0 to int x.rank - 1 do
                let hasLoBound = i < x.loBounds.Length
                let loBound() = int x.loBounds.[i]
                let hasSize = i < x.sizes.Length
                let size() = int x.sizes.[i]

                if hasLoBound then
                    yield string <| loBound()
                    yield "..."
                    if hasSize then
                        yield string <| loBound() + size() - 1
                elif hasSize then
                    yield string <| size()
                else
                    yield ""
        |]

    static member FromBlob (blob : byte list ref) =
        let readByte = makeReadByteFun blob
        let rank = readCompressedUnsignedInt readByte
        let numSizes = readCompressedUnsignedInt readByte
        let sizes = [|for _ in 1u .. numSizes -> readCompressedUnsignedInt readByte|]
        let numLoBounds = readCompressedUnsignedInt readByte
        let loBounds = [|for _ in 1u .. numLoBounds -> readCompressedInt readByte|]

        {ArrayShape.rank = rank; sizes = sizes; loBounds = loBounds}

and GenericTypeInst = {
    // if isClass is false then it is a valuetype
    isClass : bool
    genericType : TypeDefRefOrSpec
    typeParams : TypeBlob list
}
with
    static member TypesMatch (gt1 : GenericTypeInst) (gt2 : GenericTypeInst) : bool =
        let rec tyParamsMatch (tyParams1 : TypeBlob list) (tyParams2 : TypeBlob list) =
            match tyParams1, tyParams2 with
            | ty1 :: tyTail1, ty2 :: tyTail2 ->
                TypeBlob.TypesMatch ty1 ty2 && tyParamsMatch tyTail1 tyTail2
            | [], [] -> true
            | _ -> false

        gt1.isClass = gt2.isClass
        && TypeDefRefOrSpec.SameType gt1.genericType gt2.genericType
        && tyParamsMatch gt1.typeParams gt2.typeParams

and [<RequireQualifiedAccess>] TypeSpecBlob =
    | Ptr of List<CustomModBlob> * Option<TypeBlob>
    | FnPtr of MethodDefOrRefSig
    | Array of TypeBlob * ArrayShape
    | SzArray of List<CustomModBlob> * TypeBlob
    | GenericInst of GenericTypeInst

    // TODO VAR and MVAR are not in the spec but they do seem to show up in assemblies (well
    // at least MVAR does. I haven't yet confirmed that VAR does)
    | MVar of uint32
    | Var of uint32
    with
        member x.AsTypeBlob() : TypeBlob =
            match x with
            | Ptr (custMods, tyOpt) -> TypeBlob.Ptr (custMods, tyOpt)
            | FnPtr meth -> TypeBlob.FnPtr meth
            | Array (ty, shape) -> TypeBlob.Array (ty, shape)
            | SzArray (custMods, ty) -> TypeBlob.SzArray (custMods, ty)
            | GenericInst gInst -> TypeBlob.GenericInst gInst

            // TODO VAR and MVAR are not in the spec but they do seem to show up in assemblies (well
            // at least MVAR does. I haven't yet confirmed that VAR does)
            | MVar i -> TypeBlob.MVar i
            | Var i -> TypeBlob.Var i

        static member FromBlob (assem : Assembly) (blob : byte list ref) : TypeSpecBlob =
            match listRead blob with
            | None ->  failwith "cannot parse a type spec from an empty blob"
            | Some b ->
                let unexpEnd() = failwith "unexpected end of type"
                let custModList() = CustomModBlob.ManyFromBlob assem blob
                let readUInt() = readCompressedUnsignedInt (makeReadByteFun blob)

                match enum<ElementType>(int b) with
                | ElementType.Ptr ->
                    match !blob with
                    | [] -> unexpEnd()
                    | ElTy ElementType.Void :: _ ->
                        listSkip blob
                        Ptr(custModList(), None)
                    | _ ->
                        Ptr(custModList(), Some(TypeBlob.FromBlob assem blob))

                | ElementType.FnPtr -> FnPtr(MethodDefOrRefSig.FromBlob assem blob)
                | ElementType.Array ->
                    Array(TypeBlob.FromBlob assem blob, ArrayShape.FromBlob blob)
                | ElementType.SzArray ->
                    SzArray(custModList(), TypeBlob.FromBlob assem blob)
                | ElementType.GenericInst ->
                    match listRead blob with
                    | None -> unexpEnd()
                    | Some b ->
                        let isClass =
                            match enum<ElementType>(int b) with
                            | ElementType.Class -> true
                            | ElementType.ValueType -> false
                            | et ->
                                failwithf "unexpected element type while reading generic instruction blob: %A" et
                        let tyDefRefSpecBlob = TypeDefRefOrSpec.FromBlob assem blob
                        let tys =
                            let genArgCount = readCompressedUnsignedInt (makeReadByteFun blob)
                            [for _ in 1u .. genArgCount -> TypeBlob.FromBlob assem blob]

                        //GenericInst(isClass, tyDefRefSpecBlob, tys)
                        let genTyInst = {
                            GenericTypeInst.isClass = isClass
                            genericType = tyDefRefSpecBlob
                            typeParams = tys
                        }
                        GenericInst genTyInst
                | ElementType.MVar -> MVar(readUInt())
                | ElementType.Var -> Var(readUInt())
                | et ->
                    failwithf "the following element type is not valid for a type spec: %A" et
