module Fig.AbstractCode

open Fig.AssemblyParser
open System.IO

type CodeType =
    | ILCodeType
    | NativeCodeType
    | RuntimeCodeType

type MemberAccess =
    | CompilerControlled
    | Private
    | FamANDAssem
    | Assem
    | Family
    | FamORAssem
    | Public

type Parameter (r : BinaryReader, mt : MetadataTables, selfIndex : int) =
    let pRow = mt.paramRows.[selfIndex]
    do failwith "implement me!"

type MethodDef (r : BinaryReader, secHdrs : SectionHeader list, mt : MetadataTables, selfIndex : int) =
    let mdRow = mt.methodDefs.[selfIndex]
    let isFlagSet mask = mdRow.flags &&& mask <> 0us
    let isImplFlagSet mask = mdRow.implFlags &&& mask <> 0us

    member x.TableRow with get () = mdRow
    member x.IsCtor with get () = mdRow.name = ".ctor"
    member x.IsCCtor with get () = mdRow.name = ".cctor"
    
    member x.CodeType
        with get () =
            // Section 22.26 item 34.b
            // ImplFlags.CodeTypeMask shall have exactly one of the following values:
            // Native,  CIL, or Runtime
            match mdRow.implFlags &&& 0x0003us with
            | 0x0000us -> ILCodeType
            | 0x0001us -> NativeCodeType
            | 0x0003us -> RuntimeCodeType
            | n -> failwithf "bad CodeTypeMask value: 0x%X" n

    member x.IsManaged      with get () = not (isImplFlagSet 0x0004us)
    member x.IsForwardRef   with get () = isImplFlagSet 0x0010us
    member x.IsSynchronized with get () = isImplFlagSet 0x0020us
    member x.NoInlining     with get () = isImplFlagSet 0x0008us
    member x.NoOptimization with get () = isImplFlagSet 0x0040us

    member x.MemberAccess
        with get () =
            // The MemberAccessMask (23.1.10) subfield of Flags shall contain precisely one of
            // CompilerControlled, Private, FamANDAssem, Assem, Family, FamORAssem, or Public
            match mdRow.flags &&& 0x0007us with
            | 0x0000us -> CompilerControlled
            | 0x0001us -> Private
            | 0x0002us -> FamANDAssem
            | 0x0003us -> Assem
            | 0x0004us -> Family
            | 0x0005us -> FamORAssem
            | 0x0006us -> Public
            | n -> failwithf "bad MemberAccessMask value: 0x%X" n

    // Section 22.26 item 7. The following combined bit settings in Flags are invalid
    // a. Static | Final
    // b. Static | Virtual
    // c. Static | NewSlot
    // d. Final  | Abstract
    // e. Abstract | PinvokeImpl
    // f. CompilerControlled | SpecialName
    // g. CompilerControlled | RTSpecialName
    member x.IsStatic       with get () = isFlagSet 0x0010us
    member x.IsFinal        with get () = isFlagSet 0x0020us
    member x.IsVirtual      with get () = isFlagSet 0x0040us
    member x.HideBySig      with get () = isFlagSet 0x0080us
    member x.NewVTableSlot  with get () = isFlagSet 0x0100us
    member x.IsStrict       with get () = isFlagSet 0x0200us
    member x.IsAbstract     with get () = isFlagSet 0x0400us
    member x.SpecialName    with get () = isFlagSet 0x0800us
    member x.PInvokeImpl    with get () = isFlagSet 0x2000us
    member x.RTSpecialName  with get () = isFlagSet 0x1000us
    member x.HasSecurity    with get () = isFlagSet 0x4000us
    member x.RequireSecObj  with get () = isFlagSet 0x8000us

    member x.Parameters
        with get () =
            let fstParamIndex = int32 mdRow.paramIndex
            let lastParamIndex =
                let isLastMethodDef = selfIndex = mt.methodDefs.Length - 1
                if isLastMethodDef then
                    mt.paramRows.Length - 1
                else
                    int32 mt.methodDefs.[selfIndex + 1].paramIndex - 1

            [|for i in fstParamIndex .. lastParamIndex -> new Parameter(r, mt, i)|]

    member x.MethodBody
        with get () =
            if mdRow.rva = 0u then
                // Section 22.26 item 33. If RVA = 0, then either:
                // o Flags.Abstract = 1, or
                // o ImplFlags.Runtime = 1, or
                // o Flags.PinvokeImpl = 1
                if not (x.IsAbstract || x.CodeType = RuntimeCodeType || x.PInvokeImpl) then
                    failwith "bad method body RVA"
                None
            else
                // Section 22.26 item 34. If RVA != 0, then:
                // a. Flags.Abstract shall be 0, and
                // b. ImplFlags.CodeTypeMask shall have exactly one of the following values: Native,  CIL, or
                //    Runtime, and
                // c. RVA shall point into the CIL code stream in this file
                // TODO check these conditions

                r.BaseStream.Seek (rvaToDiskPos secHdrs mdRow.rva, SeekOrigin.Begin) |> ignore
                Some (readMethodBody r)

