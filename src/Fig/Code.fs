module Fig.Code

open Mono.Cecil
open Mono.Cecil.Cil

let failwithf fmt = Printf.ksprintf failwith fmt

type CodeBlock (offsetBytes : int) =
    let mutable myInsts = [||] : AbstractInstruction array
    
    /// the instructions in this code block
    member x.Instructions
        with get () = myInsts
        and set insts = myInsts <- insts
    
    /// the offset in bytes is relative to the function body so it acts
    /// as a unique ID for a given block in a function
    member x.OffsetBytes with get () = offsetBytes

and AbstractInstruction =
    | Add
    | And
    | Beq of CodeBlock
    | Bge of CodeBlock
    | Bgt of CodeBlock
    | Ble of CodeBlock
    | Blt of CodeBlock
    | BneUn of CodeBlock
    | BgeUn of CodeBlock
    | BgtUn of CodeBlock
    | BleUn of CodeBlock
    | BltUn of CodeBlock
    | Br of CodeBlock
    | Break
    | Brfalse of CodeBlock
    | Brtrue of CodeBlock
//    | Call of bool * MetadataToken
//    | Calli of bool * MetadataToken
//    | Callvirt of MetadataToken option * bool * MetadataToken
    | ConvI1
    | ConvI2
    | ConvI4
    | ConvI8
    | ConvR4
    | ConvR8
    | ConvU4
    | ConvU8
//    | Cpobj of MetadataToken
    | Div
    | DivUn
    | Dup
//    | Jmp of MetadataToken
//    | Ldarg of uint16
//    | Ldarga of uint16
//    | LdcI4 of int
//    | LdcI8 of int64
//    | LdcR4 of single
//    | LdcR8 of double
//    | LdindU1 of byte option
//    | LdindI2 of byte option
//    | LdindU2 of byte option
//    | LdindI4 of byte option
//    | LdindU4 of byte option
//    | LdindI8 of byte option
//    | LdindI of byte option
//    | LdindR4 of byte option
//    | LdindR8 of byte option
//    | LdindRef of byte option
//    | Ldloc of uint16
//    | Ldloca of uint16
    | Ldnull
//    | Ldobj of byte option * MetadataToken
//    | Ldstr of MetadataToken
    | Mul
    | Neg
    | Nop
    | Not
//    | Newobj of MetadataToken
    | Or
    | Pop
    | Rem
    | RemUn
    | Ret
    | Shl
    | Shr
    | ShrUn
//    | Starg of uint16
//    | StindRef of byte option
//    | StindI1 of byte option
//    | StindI2 of byte option
//    | StindI4 of byte option
//    | StindI8 of byte option
//    | StindR4 of byte option
//    | StindR8 of byte option
//    | Stloc of uint16
    | Sub
//    | Switch of int array
    | Xor
//    | Castclass of MetadataToken
//    | Isinst of MetadataToken
    | ConvRUn
//    | Unbox of MetadataToken
//    | Throw
//    | Ldfld of byte option * MetadataToken
//    | Ldflda of byte option * MetadataToken
//    | Stfld of byte option * MetadataToken
//    | Ldsfld of MetadataToken
//    | Ldsflda of MetadataToken
//    | Stsfld of MetadataToken
//    | Stobj of byte option * MetadataToken
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
//    | Box of MetadataToken
//    | Newarr of MetadataToken
    | Ldlen
//    | Ldelema of MetadataToken
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
//    | Ldelem of MetadataToken
//    | Stelem of MetadataToken
//    | UnboxAny of MetadataToken
    | ConvOvfI1
    | ConvOvfU1
    | ConvOvfI2
    | ConvOvfU2
    | ConvOvfI4
    | ConvOvfU4
    | ConvOvfI8
    | ConvOvfU8
//    | Refanyval of MetadataToken
    | Ckfinite
//    | Mkrefany of MetadataToken
//    | Ldtoken of MetadataToken
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
//    | Leave of int
//    | StindI of byte option
    | ConvU
    | Arglist
    | Ceq
    | Cgt
    | CgtUn
    | Clt
    | CltUn
//    | Ldftn of MetadataToken
//    | Ldvirtftn of MetadataToken
    | Localloc
    | Endfilter
//    | Initobj of MetadataToken
    | Cpblk
//    | Initblk of byte option
    | Rethrow
//    | Sizeof of MetadataToken
    | Refanytype

let toCodeBlocks (insts : Instruction array) =

    let branchDestOffsets = seq {
        for inst in insts do
            match inst.OpCode.OperandType with
            | OperandType.ShortInlineBrTarget
            | OperandType.InlineBrTarget ->
                let destInst = inst.Operand :?> Instruction
                yield destInst.Offset
            | OperandType.InlineSwitch ->
                for destInst in inst.Operand :?> Instruction array do
                    yield destInst.Offset
            | _ -> ()}

    let codeBlocks =
        Set.ofSeq branchDestOffsets
        |> Array.ofSeq
        |> Array.sort
        |> Array.map (fun offset -> CodeBlock offset)

    let instOffsets = [|for inst in insts -> inst.Offset|]
    let indexOfInstAt offset =
        let i = System.Array.BinarySearch (instOffsets, offset)
        if i >= 0 then
            i
        else
            failwithf "bad instruction offset: %i" offset
    let blockStartIndexes =
        [|for bl in codeBlocks -> indexOfInstAt bl.OffsetBytes|]
    let blockInstCounts = [|
        for ii in 0 .. blockStartIndexes.Length - 1 do
            let currStart = blockStartIndexes.[ii]
            let currEnd =
                if ii = blockStartIndexes.Length - 1 then
                    insts.Length
                else
                    blockStartIndexes.[ii + 1]
            yield currEnd - currStart|]

    let opCodeBlock () = CodeBlock 0
    
    let toAbstInst (inst : Instruction) =
        match inst.OpCode.Code with
        | Code.Nop -> Nop
        | Code.Break -> Break
    //    | Code.Ldarg_0 ->
    //    | Code.Ldarg_1 ->
    //    | Code.Ldarg_2 ->
    //    | Code.Ldarg_3 ->
    //    | Code.Ldloc_0 ->
    //    | Code.Ldloc_1 ->
    //    | Code.Ldloc_2 ->
    //    | Code.Ldloc_3 ->
    //    | Code.Stloc_0 ->
    //    | Code.Stloc_1 ->
    //    | Code.Stloc_2 ->
    //    | Code.Stloc_3 ->
    //    | Code.Ldarg_S ->
    //    | Code.Ldarga_S ->
    //    | Code.Starg_S ->
    //    | Code.Ldloc_S ->
    //    | Code.Ldloca_S ->
    //    | Code.Stloc_S ->
        | Code.Ldnull -> Ldnull
    //    | Code.Ldc_I4_M1 ->
    //    | Code.Ldc_I4_0 ->
    //    | Code.Ldc_I4_1 ->
    //    | Code.Ldc_I4_2 ->
    //    | Code.Ldc_I4_3 ->
    //    | Code.Ldc_I4_4 ->
    //    | Code.Ldc_I4_5 ->
    //    | Code.Ldc_I4_6 ->
    //    | Code.Ldc_I4_7 ->
    //    | Code.Ldc_I4_8 ->
    //    | Code.Ldc_I4_S ->
    //    | Code.Ldc_I4 ->
    //    | Code.Ldc_I8 ->
    //    | Code.Ldc_R4 ->
    //    | Code.Ldc_R8 ->
        | Code.Dup -> Dup
        | Code.Pop -> Pop
    //    | Code.Jmp ->
    //    | Code.Call ->
    //    | Code.Calli ->
        | Code.Ret -> Ret
        | Code.Br_S -> Br <| opCodeBlock ()
        | Code.Brfalse_S -> Brfalse <| opCodeBlock ()
        | Code.Brtrue_S -> Brtrue <| opCodeBlock ()
        | Code.Beq_S -> Beq <| opCodeBlock ()
        | Code.Bge_S -> Bge <| opCodeBlock ()
        | Code.Bgt_S -> Bgt <| opCodeBlock ()
        | Code.Ble_S -> Ble <| opCodeBlock ()
        | Code.Blt_S -> Blt <| opCodeBlock ()
        | Code.Bne_Un_S -> BneUn <| opCodeBlock ()
        | Code.Bge_Un_S -> BgeUn <| opCodeBlock ()
        | Code.Bgt_Un_S -> BgtUn <| opCodeBlock ()
        | Code.Ble_Un_S -> BleUn <| opCodeBlock ()
        | Code.Blt_Un_S -> BltUn <| opCodeBlock ()
        | Code.Br -> Br <| opCodeBlock ()
        | Code.Brfalse -> Brfalse <| opCodeBlock ()
        | Code.Brtrue -> Brtrue <| opCodeBlock ()
        | Code.Beq -> Beq <| opCodeBlock ()
        | Code.Bge -> Bge <| opCodeBlock ()
        | Code.Bgt -> Bgt <| opCodeBlock ()
        | Code.Ble -> Ble <| opCodeBlock ()
        | Code.Blt -> Blt <| opCodeBlock ()
        | Code.Bne_Un -> BneUn <| opCodeBlock ()
        | Code.Bge_Un -> BgeUn <| opCodeBlock ()
        | Code.Bgt_Un -> BgtUn <| opCodeBlock ()
        | Code.Ble_Un -> BleUn <| opCodeBlock ()
        | Code.Blt_Un -> BltUn <| opCodeBlock ()
    //    | Code.Switch ->
    //    | Code.Ldind_I1 ->
    //    | Code.Ldind_U1 ->
    //    | Code.Ldind_I2 ->
    //    | Code.Ldind_U2 ->
    //    | Code.Ldind_I4 ->
    //    | Code.Ldind_U4 ->
    //    | Code.Ldind_I8 ->
    //    | Code.Ldind_I ->
    //    | Code.Ldind_R4 ->
    //    | Code.Ldind_R8 ->
    //    | Code.Ldind_Ref ->
    //    | Code.Stind_Ref ->
    //    | Code.Stind_I1 ->
    //    | Code.Stind_I2 ->
    //    | Code.Stind_I4 ->
    //    | Code.Stind_I8 ->
    //    | Code.Stind_R4 ->
    //    | Code.Stind_R8 ->
        | Code.Add -> Add
        | Code.Sub -> Sub
        | Code.Mul -> Mul
        | Code.Div -> Div
        | Code.Div_Un -> DivUn
        | Code.Rem -> Rem
        | Code.Rem_Un -> RemUn
        | Code.And -> And
        | Code.Or -> Or
        | Code.Xor -> Xor
        | Code.Shl -> Shl
        | Code.Shr -> Shr
        | Code.Shr_Un -> ShrUn
        | Code.Neg -> Neg
        | Code.Not -> Not
        | Code.Conv_I1 -> ConvI1
        | Code.Conv_I2 -> ConvI2
        | Code.Conv_I4 -> ConvI4
        | Code.Conv_I8 -> ConvI8
        | Code.Conv_R4 -> ConvR4
        | Code.Conv_R8 -> ConvR8
        | Code.Conv_U4 -> ConvU4
        | Code.Conv_U8 -> ConvU8
    //    | Code.Callvirt ->
    //    | Code.Cpobj ->
    //    | Code.Ldobj ->
    //    | Code.Ldstr ->
    //    | Code.Newobj ->
    //    | Code.Castclass ->
    //    | Code.Isinst ->
        | Code.Conv_R_Un -> ConvRUn
    //    | Code.Unbox ->
    //    | Code.Throw ->
    //    | Code.Ldfld ->
    //    | Code.Ldflda ->
    //    | Code.Stfld ->
    //    | Code.Ldsfld ->
    //    | Code.Ldsflda ->
    //    | Code.Stsfld ->
    //    | Code.Stobj ->
        | Code.Conv_Ovf_I1_Un -> ConvOvfI1Un
        | Code.Conv_Ovf_I2_Un -> ConvOvfI2Un
        | Code.Conv_Ovf_I4_Un -> ConvOvfI4Un
        | Code.Conv_Ovf_I8_Un -> ConvOvfI8Un
        | Code.Conv_Ovf_U1_Un -> ConvOvfU1Un
        | Code.Conv_Ovf_U2_Un -> ConvOvfU2Un
        | Code.Conv_Ovf_U4_Un -> ConvOvfU4Un
        | Code.Conv_Ovf_U8_Un -> ConvOvfU8Un
        | Code.Conv_Ovf_I_Un -> ConvOvfIUn
        | Code.Conv_Ovf_U_Un -> ConvOvfUUn
    //    | Code.Box ->
    //    | Code.Newarr ->
        | Code.Ldlen -> Ldlen
    //    | Code.Ldelema ->
        | Code.Ldelem_I1 -> LdelemI1
        | Code.Ldelem_U1 -> LdelemU1
        | Code.Ldelem_I2 -> LdelemI2
        | Code.Ldelem_U2 -> LdelemU2
        | Code.Ldelem_I4 -> LdelemI4
        | Code.Ldelem_U4 -> LdelemU4
        | Code.Ldelem_I8 -> LdelemI8
        | Code.Ldelem_I -> LdelemI
        | Code.Ldelem_R4 -> LdelemR4
        | Code.Ldelem_R8 -> LdelemR8
        | Code.Ldelem_Ref -> LdelemRef
        | Code.Stelem_I -> StelemI
        | Code.Stelem_I1 -> StelemI1
        | Code.Stelem_I2 -> StelemI2
        | Code.Stelem_I4 -> StelemI4
        | Code.Stelem_I8 -> StelemI8
        | Code.Stelem_R4 -> StelemR4
        | Code.Stelem_R8 -> StelemR8
        | Code.Stelem_Ref -> StelemRef
    //    | Code.Ldelem_Any ->
    //    | Code.Stelem_Any ->
    //    | Code.Unbox_Any ->
        | Code.Conv_Ovf_I1 -> ConvOvfI1
        | Code.Conv_Ovf_U1 -> ConvOvfU1
        | Code.Conv_Ovf_I2 -> ConvOvfI2
        | Code.Conv_Ovf_U2 -> ConvOvfU2
        | Code.Conv_Ovf_I4 -> ConvOvfI4
        | Code.Conv_Ovf_U4 -> ConvOvfU4
        | Code.Conv_Ovf_I8 -> ConvOvfI8
        | Code.Conv_Ovf_U8 -> ConvOvfU8
    //    | Code.Refanyval ->
        | Code.Ckfinite -> Ckfinite
    //    | Code.Mkrefany ->
    //    | Code.Ldtoken ->
        | Code.Conv_U2 -> ConvU2
        | Code.Conv_U1 -> ConvU1
        | Code.Conv_I -> ConvI
        | Code.Conv_Ovf_I -> ConvOvfI
        | Code.Conv_Ovf_U -> ConvOvfU
        | Code.Add_Ovf -> AddOvf
        | Code.Add_Ovf_Un -> AddOvfUn
        | Code.Mul_Ovf -> MulOvf
        | Code.Mul_Ovf_Un -> MulOvfUn
        | Code.Sub_Ovf -> SubOvf
        | Code.Sub_Ovf_Un -> SubOvfUn
        | Code.Endfinally -> Endfinally
    //    | Code.Leave ->
    //    | Code.Leave_S ->
    //    | Code.Stind_I ->
        | Code.Conv_U -> ConvU
        | Code.Arglist -> Arglist
        | Code.Ceq -> Ceq
        | Code.Cgt -> Cgt
        | Code.Cgt_Un -> CgtUn
        | Code.Clt -> Clt
        | Code.Clt_Un -> CltUn
    //    | Code.Ldftn ->
    //    | Code.Ldvirtftn ->
    //    | Code.Ldarg ->
    //    | Code.Ldarga ->
    //    | Code.Starg ->
    //    | Code.Ldloc ->
    //    | Code.Ldloca ->
    //    | Code.Stloc ->
        | Code.Localloc -> Localloc
        | Code.Endfilter -> Endfilter
    //    | Code.Unaligned ->
    //    | Code.Volatile ->
    //    | Code.Tail ->
    //    | Code.Initobj ->
    //    | Code.Constrained ->
        | Code.Cpblk -> Cpblk
    //    | Code.Initblk ->
    //    | Code.No ->
        | Code.Rethrow -> Rethrow
    //    | Code.Sizeof ->
        | Code.Refanytype -> Refanytype
    //    | Code.Readonly ->

    [|for inst in insts do
        yield toAbstInst inst|]

//[<EntryPoint>]
//let main args =
//    match args with
//    | [|assemFile|] ->
//        let assem = AssemblyDefinition.ReadAssembly assemFile
//        let mainModule = assem.MainModule
//        for ty in assem.MainModule.Types do
//            for meth in ty.Methods do
//                let body = meth.Body
//                printfn "BODY=%A" body
//
//        // exit success
//        0
//    | _ ->
//        failwith "bad command line args"

