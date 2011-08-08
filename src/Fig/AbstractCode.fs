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

and AbstractInstruction =
    | AbstAdd
    | AbstAnd
    | AbstBeq of int
    | AbstBge of int
    | AbstBgt of int
    | AbstBle of int
    | AbstBlt of int
    | AbstBneUn of int
    | AbstBgeUn of int
    | AbstBgtUn of int
    | AbstBleUn of int
    | AbstBltUn of int
    | AbstBr of int
    | AbstBreak
    | AbstBrfalse of int
    | AbstBrtrue of int
    | AbstCall of bool * MetadataToken
    | AbstCalli of bool * MetadataToken
    | AbstCallvirt of MetadataToken option * bool * MetadataToken
    | AbstConvI1
    | AbstConvI2
    | AbstConvI4
    | AbstConvI8
    | AbstConvR4
    | AbstConvR8
    | AbstConvU4
    | AbstConvU8
    | AbstCpobj of MetadataToken
    | AbstDiv
    | AbstDivUn
    | AbstDup
    | AbstJmp of MetadataToken
    | AbstLdarg of uint16
    | AbstLdarga of uint16
    | AbstLdcI4 of int
    | AbstLdcI8 of int64
    | AbstLdcR4 of single
    | AbstLdcR8 of double
    | AbstLdindU1 of byte option
    | AbstLdindI2 of byte option
    | AbstLdindU2 of byte option
    | AbstLdindI4 of byte option
    | AbstLdindU4 of byte option
    | AbstLdindI8 of byte option
    | AbstLdindI of byte option
    | AbstLdindR4 of byte option
    | AbstLdindR8 of byte option
    | AbstLdindRef of byte option
    | AbstLdloc of uint16
    | AbstLdloca of uint16
    | AbstLdnull
    | AbstLdobj of byte option * MetadataToken
    | AbstLdstr of MetadataToken
    | AbstMul
    | AbstNeg
    | AbstNop
    | AbstNot
    | AbstNewobj of MetadataToken
    | AbstOr
    | AbstPop
    | AbstRem
    | AbstRemUn
    | AbstRet
    | AbstShl
    | AbstShr
    | AbstShrUn
    | AbstStarg of uint16
    | AbstStindRef of byte option
    | AbstStindI1 of byte option
    | AbstStindI2 of byte option
    | AbstStindI4 of byte option
    | AbstStindI8 of byte option
    | AbstStindR4 of byte option
    | AbstStindR8 of byte option
    | AbstStloc of uint16
    | AbstSub
    | AbstSwitch of int array
    | AbstXor
    | AbstCastclass of MetadataToken
    | AbstIsinst of MetadataToken
    | AbstConvRUn
    | AbstUnbox of MetadataToken
    | AbstThrow
    | AbstLdfld of byte option * MetadataToken
    | AbstLdflda of byte option * MetadataToken
    | AbstStfld of byte option * MetadataToken
    | AbstLdsfld of MetadataToken
    | AbstLdsflda of MetadataToken
    | AbstStsfld of MetadataToken
    | AbstStobj of byte option * MetadataToken
    | AbstConvOvfI1Un
    | AbstConvOvfI2Un
    | AbstConvOvfI4Un
    | AbstConvOvfI8Un
    | AbstConvOvfU1Un
    | AbstConvOvfU2Un
    | AbstConvOvfU4Un
    | AbstConvOvfU8Un
    | AbstConvOvfIUn
    | AbstConvOvfUUn
    | AbstBox of MetadataToken
    | AbstNewarr of MetadataToken
    | AbstLdlen
    | AbstLdelema of MetadataToken
    | AbstLdelemI1
    | AbstLdelemU1
    | AbstLdelemI2
    | AbstLdelemU2
    | AbstLdelemI4
    | AbstLdelemU4
    | AbstLdelemI8
    | AbstLdelemI
    | AbstLdelemR4
    | AbstLdelemR8
    | AbstLdelemRef
    | AbstStelemI
    | AbstStelemI1
    | AbstStelemI2
    | AbstStelemI4
    | AbstStelemI8
    | AbstStelemR4
    | AbstStelemR8
    | AbstStelemRef
    | AbstLdelem of MetadataToken
    | AbstStelem of MetadataToken
    | AbstUnboxAny of MetadataToken
    | AbstConvOvfI1
    | AbstConvOvfU1
    | AbstConvOvfI2
    | AbstConvOvfU2
    | AbstConvOvfI4
    | AbstConvOvfU4
    | AbstConvOvfI8
    | AbstConvOvfU8
    | AbstRefanyval of MetadataToken
    | AbstCkfinite
    | AbstMkrefany of MetadataToken
    | AbstLdtoken of MetadataToken
    | AbstConvU2
    | AbstConvU1
    | AbstConvI
    | AbstConvOvfI
    | AbstConvOvfU
    | AbstAddOvf
    | AbstAddOvfUn
    | AbstMulOvf
    | AbstMulOvfUn
    | AbstSubOvf
    | AbstSubOvfUn
    | AbstEndfinally
    | AbstLeave of int
    | AbstStindI of byte option
    | AbstConvU
    | AbstArglist
    | AbstCeq
    | AbstCgt
    | AbstCgtUn
    | AbstClt
    | AbstCltUn
    | AbstLdftn of MetadataToken
    | AbstLdvirtftn of MetadataToken
    | AbstLocalloc
    | AbstEndfilter
    | AbstInitobj of MetadataToken
    | AbstCpblk
    | AbstInitblk of byte option
    | AbstRethrow
    | AbstSizeof of MetadataToken
    | AbstRefanytype

let toAbstractInstruction (inst : Instruction) =
    match inst with
    | Add -> AbstAdd
    | And -> AbstAnd
    | Beq tgt -> AbstBeq tgt // TODO change target to a block for all of the branches
    | Bge tgt -> AbstBge tgt
    | Bgt tgt -> AbstBgt tgt
    | Ble tgt -> AbstBle tgt
    | Blt tgt -> AbstBlt tgt
    | BneUn tgt -> AbstBneUn tgt
    | BgeUn tgt -> AbstBgeUn tgt
    | BgtUn tgt -> AbstBgtUn tgt
    | BleUn tgt -> AbstBleUn tgt
    | BltUn tgt -> AbstBltUn tgt
    | Br tgt -> AbstBr tgt
    | Break -> AbstBreak
    | Brfalse tgt -> AbstBrfalse tgt
    | Brtrue tgt -> AbstBrtrue tgt
    | Call (isTail, metaTok) -> AbstCall (isTail, metaTok)
    | Calli (isTail, metaTok) -> AbstCalli (isTail, metaTok)
    | Callvirt (constrainedOpt, isTail, metaTok) -> AbstCallvirt (constrainedOpt, isTail, metaTok)
    | ConvI1 -> AbstConvI1
    | ConvI2 -> AbstConvI2
    | ConvI4 -> AbstConvI4
    | ConvI8 -> AbstConvI8
    | ConvR4 -> AbstConvR4
    | ConvR8 -> AbstConvR8
    | ConvU4 -> AbstConvU4
    | ConvU8 -> AbstConvU8
    | Cpobj typeMetaTok -> AbstCpobj typeMetaTok
    | Div -> AbstDiv
    | DivUn -> AbstDivUn
    | Dup -> AbstDup
    | Jmp methodMetaTok -> AbstJmp methodMetaTok
    | Ldarg argIndex -> AbstLdarg argIndex
    | Ldarga argIndex -> AbstLdarga argIndex
    | LdcI4 c -> AbstLdcI4 c
    | LdcI8 c -> AbstLdcI8 c
    | LdcR4 c -> AbstLdcR4 c
    | LdcR8 c -> AbstLdcR8 c
    | LdindU1 unalignedOpt -> AbstLdindU1 unalignedOpt
    | LdindI2 unalignedOpt -> AbstLdindI2 unalignedOpt
    | LdindU2 unalignedOpt -> AbstLdindU2 unalignedOpt
    | LdindI4 unalignedOpt -> AbstLdindI4 unalignedOpt
    | LdindU4 unalignedOpt -> AbstLdindU4 unalignedOpt
    | LdindI8 unalignedOpt -> AbstLdindI8 unalignedOpt
    | LdindI unalignedOpt -> AbstLdindI unalignedOpt
    | LdindR4 unalignedOpt -> AbstLdindR4 unalignedOpt
    | LdindR8 unalignedOpt -> AbstLdindR8 unalignedOpt
    | LdindRef unalignedOpt -> AbstLdindRef unalignedOpt
    | Ldloc varIndex -> AbstLdloc varIndex
    | Ldloca varIndex -> AbstLdloca varIndex
    | Ldnull -> AbstLdnull
    | Ldobj (unalignedOpt, typeTok) -> AbstLdobj (unalignedOpt, typeTok)
    | Ldstr strTok -> AbstLdstr strTok
    | Mul -> AbstMul
    | Neg -> AbstNeg
    | Nop -> AbstNop
    | Not -> AbstNot
    | Newobj ctorTok -> AbstNewobj ctorTok
    | Or -> AbstOr
    | Pop -> AbstPop
    | Rem -> AbstRem
    | RemUn -> AbstRemUn
    | Ret -> AbstRet
    | Shl -> AbstShl
    | Shr -> AbstShr
    | ShrUn -> AbstShrUn
    | Starg argIndex -> AbstStarg argIndex
    | StindRef unalignedOpt -> AbstStindRef unalignedOpt
    | StindI1 unalignedOpt -> AbstStindI1 unalignedOpt
    | StindI2 unalignedOpt -> AbstStindI2 unalignedOpt
    | StindI4 unalignedOpt -> AbstStindI4 unalignedOpt
    | StindI8 unalignedOpt -> AbstStindI8 unalignedOpt
    | StindR4 unalignedOpt -> AbstStindR4 unalignedOpt
    | StindR8 unalignedOpt -> AbstStindR8 unalignedOpt
    | Stloc varIndex -> AbstStloc varIndex
    | Sub -> AbstSub
    | Switch tgtArray -> AbstSwitch tgtArray
    | Xor -> AbstXor
    | Castclass typeTok -> AbstCastclass typeTok
    | Isinst typeTok -> AbstIsinst typeTok
    | ConvRUn -> AbstConvRUn
    | Unbox valTypeTok -> AbstUnbox valTypeTok
    | Throw -> AbstThrow
    | Ldfld (unalignedOpt, fieldTok) -> AbstLdfld (unalignedOpt, fieldTok)
    | Ldflda (unalignedOpt, fieldTok) -> AbstLdflda (unalignedOpt, fieldTok)
    | Stfld (unalignedOpt, fieldTok) -> AbstStfld (unalignedOpt, fieldTok)
    | Ldsfld fieldTok -> AbstLdsfld fieldTok
    | Ldsflda fieldTok -> AbstLdsflda fieldTok
    | Stsfld fieldTok -> AbstStsfld fieldTok
    | Stobj (unalignedOpt, typeTok) -> AbstStobj (unalignedOpt, typeTok)
    | ConvOvfI1Un -> AbstConvOvfI1Un
    | ConvOvfI2Un -> AbstConvOvfI2Un
    | ConvOvfI4Un -> AbstConvOvfI4Un
    | ConvOvfI8Un -> AbstConvOvfI8Un
    | ConvOvfU1Un -> AbstConvOvfU1Un
    | ConvOvfU2Un -> AbstConvOvfU2Un
    | ConvOvfU4Un -> AbstConvOvfU4Un
    | ConvOvfU8Un -> AbstConvOvfU8Un
    | ConvOvfIUn -> AbstConvOvfIUn
    | ConvOvfUUn -> AbstConvOvfUUn
    | Box typeTok -> AbstBox typeTok
    | Newarr elemTypeTok -> AbstNewarr elemTypeTok
    | Ldlen -> AbstLdlen
    | Ldelema elemTypeTok -> AbstLdelema elemTypeTok
    | LdelemI1 -> AbstLdelemI1
    | LdelemU1 -> AbstLdelemU1
    | LdelemI2 -> AbstLdelemI2
    | LdelemU2 -> AbstLdelemU2
    | LdelemI4 -> AbstLdelemI4
    | LdelemU4 -> AbstLdelemU4
    | LdelemI8 -> AbstLdelemI8
    | LdelemI -> AbstLdelemI
    | LdelemR4 -> AbstLdelemR4
    | LdelemR8 -> AbstLdelemR8
    | LdelemRef -> AbstLdelemRef
    | StelemI -> AbstStelemI
    | StelemI1 -> AbstStelemI1
    | StelemI2 -> AbstStelemI2
    | StelemI4 -> AbstStelemI4
    | StelemI8 -> AbstStelemI8
    | StelemR4 -> AbstStelemR4
    | StelemR8 -> AbstStelemR8
    | StelemRef -> AbstStelemRef
    | Ldelem elemTypeTok -> AbstLdelem elemTypeTok
    | Stelem elemTypeTok -> AbstStelem elemTypeTok
    | UnboxAny typeTok -> AbstUnboxAny typeTok
    | ConvOvfI1 -> AbstConvOvfI1
    | ConvOvfU1 -> AbstConvOvfU1
    | ConvOvfI2 -> AbstConvOvfI2
    | ConvOvfU2 -> AbstConvOvfU2
    | ConvOvfI4 -> AbstConvOvfI4
    | ConvOvfU4 -> AbstConvOvfU4
    | ConvOvfI8 -> AbstConvOvfI8
    | ConvOvfU8 -> AbstConvOvfU8
    | Refanyval valTypeTok -> AbstRefanyval valTypeTok
    | Ckfinite -> AbstCkfinite
    | Mkrefany typeTok -> AbstMkrefany typeTok
    | Ldtoken metaTok -> AbstLdtoken metaTok
    | ConvU2 -> AbstConvU2
    | ConvU1 -> AbstConvU1
    | ConvI -> AbstConvI
    | ConvOvfI -> AbstConvOvfI
    | ConvOvfU -> AbstConvOvfU
    | AddOvf -> AbstAddOvf
    | AddOvfUn -> AbstAddOvfUn
    | MulOvf -> AbstMulOvf
    | MulOvfUn -> AbstMulOvfUn
    | SubOvf -> AbstSubOvf
    | SubOvfUn -> AbstSubOvfUn
    | Endfinally -> AbstEndfinally
    | Leave tgt -> AbstLeave tgt
    | StindI unalignedOpt -> AbstStindI unalignedOpt
    | ConvU -> AbstConvU
    | Arglist -> AbstArglist
    | Ceq -> AbstCeq
    | Cgt -> AbstCgt
    | CgtUn -> AbstCgtUn
    | Clt -> AbstClt
    | CltUn -> AbstCltUn
    | Ldftn methodTok -> AbstLdftn methodTok
    | Ldvirtftn methodTok -> AbstLdvirtftn methodTok
    | Localloc -> AbstLocalloc
    | Endfilter -> AbstEndfilter
    | Initobj typeTok -> AbstInitobj typeTok
    | Cpblk -> AbstCpblk
    | Initblk unalignedOpt -> AbstInitblk unalignedOpt
    | Rethrow -> AbstRethrow
    | Sizeof typeTok -> AbstSizeof typeTok
    | Refanytype -> AbstRefanytype

