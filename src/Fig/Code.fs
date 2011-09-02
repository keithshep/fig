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
    | Call of bool * MethodReference
    | Calli of bool * CallSite
    | Callvirt of TypeReference option * bool * MethodReference
    | ConvI1
    | ConvI2
    | ConvI4
    | ConvI8
    | ConvR4
    | ConvR8
    | ConvU4
    | ConvU8
    | Cpobj of TypeReference
    | Div
    | DivUn
    | Dup
    | Jmp of MethodReference
    | Ldarg of ParameterDefinition
    | Ldarga of ParameterDefinition
    | LdcI4 of int
    | LdcI8 of int64
    | LdcR4 of single
    | LdcR8 of double
    | LdindI1 of byte option
    | LdindU1 of byte option
    | LdindI2 of byte option
    | LdindU2 of byte option
    | LdindI4 of byte option
    | LdindU4 of byte option
    | LdindI8 of byte option
    | LdindI of byte option
    | LdindR4 of byte option
    | LdindR8 of byte option
    | LdindRef of byte option
    | Ldloc of VariableDefinition
    | Ldloca of VariableDefinition
    | Ldnull
    | Ldobj of byte option * TypeReference
    | Ldstr of string
    | Mul
    | Neg
    | Nop
    | Not
    | Newobj of MethodReference
    | Or
    | Pop
    | Rem
    | RemUn
    | Ret
    | Shl
    | Shr
    | ShrUn
    | Starg of ParameterDefinition
    | StindRef of byte option
    | StindI1 of byte option
    | StindI2 of byte option
    | StindI4 of byte option
    | StindI8 of byte option
    | StindR4 of byte option
    | StindR8 of byte option
    | Stloc of VariableDefinition
    | Sub
    | Switch of CodeBlock array
    | Xor
    | Castclass of TypeReference
    | Isinst of TypeReference
    | ConvRUn
    | Unbox of TypeReference
    | Throw
    | Ldfld of byte option * FieldReference
    | Ldflda of byte option * FieldReference
    | Stfld of byte option * FieldReference
    | Ldsfld of FieldReference
    | Ldsflda of FieldReference
    | Stsfld of FieldReference
    | Stobj of byte option * TypeReference
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
    | Box of TypeReference
    | Newarr of TypeReference
    | Ldlen
    | Ldelema of TypeReference
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
    | Ldelem of TypeReference
    | Stelem of TypeReference
    | UnboxAny of TypeReference
    | ConvOvfI1
    | ConvOvfU1
    | ConvOvfI2
    | ConvOvfU2
    | ConvOvfI4
    | ConvOvfU4
    | ConvOvfI8
    | ConvOvfU8
    | Refanyval of TypeReference
    | Ckfinite
    | Mkrefany of TypeReference
    | Ldtoken of IMetadataTokenProvider
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
    | Leave of CodeBlock
    | StindI of byte option
    | ConvU
    | Arglist
    | Ceq
    | Cgt
    | CgtUn
    | Clt
    | CltUn
    | Ldftn of MethodReference
    | Ldvirtftn of MethodReference
    | Localloc
    | Endfilter
    | Initobj of TypeReference
    | Cpblk
    | Initblk of byte option
    | Rethrow
    | Sizeof of TypeReference
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

    // code blocks will be determined by the destination instructions
    // of all branch instructions. Also always include the 1st instruction
    let codeBlocks =
        Set.ofSeq branchDestOffsets
        |> Set.add 0
        |> Array.ofSeq
        |> Array.sort
        |> Array.map (fun offset -> new CodeBlock(offset))

    let instOffsets = [|for inst in insts -> inst.Offset|]
    let indexOfInstAt offset =
        let i = System.Array.BinarySearch (instOffsets, offset)
        if i >= 0 then
            i
        else
            failwithf "bad instruction offset: %i" offset
    let blockInstStartIndexes =
        [|for bl in codeBlocks -> indexOfInstAt bl.OffsetBytes|]
    let blockInstCounts = [|
        for ii in 0 .. blockInstStartIndexes.Length - 1 do
            let currStart = blockInstStartIndexes.[ii]
            let currEnd =
                if ii = blockInstStartIndexes.Length - 1 then
                    insts.Length
                else
                    blockInstStartIndexes.[ii + 1]
            yield currEnd - currStart|]

    let blockForInst (inst : Instruction) =
        let i = indexOfInstAt inst.Offset
        let bIndex = System.Array.BinarySearch (blockInstStartIndexes, i)
        if bIndex >= 0 then
            codeBlocks.[bIndex]
        else
            failwithf "there is no block starting at instruction index %i" i

    let readBlock (blockIndex : int) =
        let fstInstIndex = blockInstStartIndexes.[blockIndex]
        let fstInst = insts.[fstInstIndex]
        let lstInstIndex = fstInstIndex + blockInstCounts.[blockIndex] - 1
        
        // a little sanity check first
        if blockIndex >= 1 then
            match insts.[fstInstIndex - 1].OpCode.OpCodeType with
            | OpCodeType.Prefix ->
                failwithf "code blocks should not be preceded by prefix op codes"
            | _ -> ()
        
        let currInstIndex = ref fstInstIndex
        let rec nextInst
                (constrainedPrefix : TypeReference option)
                (noPrefix : byte)
                (readonlyPrefix : bool) // TODO figure out what to do w/ readonly
                (tailPrefix : bool)
                (unalignedPrefix : byte option)
                (volatilePrefix : bool) =

            let inst = insts.[!currInstIndex]
            currInstIndex := !currInstIndex + 1
            
            let brDestCodeBlock () =
                blockForInst (inst.Operand :?> Instruction)
            
            match inst.OpCode.Code with
            | Code.Nop -> Nop
            | Code.Break -> Break
            | Code.Ldnull -> Ldnull
            | Code.Ldc_I4 -> LdcI4 (inst.Operand :?> int)
            | Code.Ldc_I8 -> LdcI8 (inst.Operand :?> int64)
            | Code.Ldc_R4 -> LdcR4 (inst.Operand :?> single)
            | Code.Ldc_R8 -> LdcR8 (inst.Operand :?> double)
            | Code.Dup -> Dup
            | Code.Pop -> Pop
            | Code.Jmp -> Jmp (inst.Operand :?> MethodReference)
            | Code.Call -> Call (tailPrefix, inst.Operand :?> MethodReference)
            | Code.Calli -> Calli (tailPrefix, inst.Operand :?> CallSite)
            | Code.Ret -> Ret
            | Code.Br -> Br <| brDestCodeBlock ()
            | Code.Brfalse -> Brfalse <| brDestCodeBlock ()
            | Code.Brtrue -> Brtrue <| brDestCodeBlock ()
            | Code.Beq -> Beq <| brDestCodeBlock ()
            | Code.Bge -> Bge <| brDestCodeBlock ()
            | Code.Bgt -> Bgt <| brDestCodeBlock ()
            | Code.Ble -> Ble <| brDestCodeBlock ()
            | Code.Blt -> Blt <| brDestCodeBlock ()
            | Code.Bne_Un -> BneUn <| brDestCodeBlock ()
            | Code.Bge_Un -> BgeUn <| brDestCodeBlock ()
            | Code.Bgt_Un -> BgtUn <| brDestCodeBlock ()
            | Code.Ble_Un -> BleUn <| brDestCodeBlock ()
            | Code.Blt_Un -> BltUn <| brDestCodeBlock ()
            | Code.Switch ->
                let destBlocks =
                    [|for destInst in inst.Operand :?> Instruction array do
                        yield blockForInst destInst|]
                Switch destBlocks
            | Code.Ldind_I1 -> LdindI1 unalignedPrefix
            | Code.Ldind_U1 -> LdindU1 unalignedPrefix
            | Code.Ldind_I2 -> LdindI2 unalignedPrefix
            | Code.Ldind_U2 -> LdindU2 unalignedPrefix
            | Code.Ldind_I4 -> LdindI4 unalignedPrefix
            | Code.Ldind_U4 -> LdindU4 unalignedPrefix
            | Code.Ldind_I8 -> LdindI8 unalignedPrefix
            | Code.Ldind_I -> LdindI unalignedPrefix
            | Code.Ldind_R4 -> LdindR4 unalignedPrefix
            | Code.Ldind_R8 -> LdindR8 unalignedPrefix
            | Code.Ldind_Ref -> LdindRef unalignedPrefix
            | Code.Stind_Ref -> StindRef unalignedPrefix
            | Code.Stind_I1 -> StindI1 unalignedPrefix
            | Code.Stind_I2 -> StindI2 unalignedPrefix
            | Code.Stind_I4 -> StindI4 unalignedPrefix
            | Code.Stind_I8 -> StindI8 unalignedPrefix
            | Code.Stind_R4 -> StindR4 unalignedPrefix
            | Code.Stind_R8 -> StindR8 unalignedPrefix
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
            | Code.Callvirt -> Callvirt (constrainedPrefix, tailPrefix, inst.Operand :?> MethodReference)
            | Code.Cpobj -> Cpobj (inst.Operand :?> TypeReference)
            | Code.Ldobj -> Ldobj (unalignedPrefix, inst.Operand :?> TypeReference)
            | Code.Ldstr -> Ldstr (inst.Operand :?> string)
            | Code.Newobj -> Newobj (inst.Operand :?> MethodReference)
            | Code.Castclass -> Castclass (inst.Operand :?> TypeReference)
            | Code.Isinst -> Isinst (inst.Operand :?> TypeReference)
            | Code.Conv_R_Un -> ConvRUn
            | Code.Unbox -> Unbox (inst.Operand :?> TypeReference)
            | Code.Throw -> Throw
            | Code.Ldfld -> Ldfld (unalignedPrefix, inst.Operand :?> FieldReference)
            | Code.Ldflda -> Ldflda (unalignedPrefix, inst.Operand :?> FieldReference)
            | Code.Stfld -> Stfld (unalignedPrefix, inst.Operand :?> FieldReference)
            | Code.Ldsfld -> Ldsfld (inst.Operand :?> FieldReference)
            | Code.Ldsflda -> Ldsflda (inst.Operand :?> FieldReference)
            | Code.Stsfld -> Stsfld (inst.Operand :?> FieldReference)
            | Code.Stobj -> Stobj (unalignedPrefix, inst.Operand :?> TypeReference)
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
            | Code.Box -> Box (inst.Operand :?> TypeReference)
            | Code.Newarr -> Newarr (inst.Operand :?> TypeReference)
            | Code.Ldlen -> Ldlen
            | Code.Ldelema -> Ldelema (inst.Operand :?> TypeReference)
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
            | Code.Ldelem_Any -> Ldelem (inst.Operand :?> TypeReference)
            | Code.Stelem_Any -> Stelem (inst.Operand :?> TypeReference)
            | Code.Unbox_Any -> UnboxAny (inst.Operand :?> TypeReference)
            | Code.Conv_Ovf_I1 -> ConvOvfI1
            | Code.Conv_Ovf_U1 -> ConvOvfU1
            | Code.Conv_Ovf_I2 -> ConvOvfI2
            | Code.Conv_Ovf_U2 -> ConvOvfU2
            | Code.Conv_Ovf_I4 -> ConvOvfI4
            | Code.Conv_Ovf_U4 -> ConvOvfU4
            | Code.Conv_Ovf_I8 -> ConvOvfI8
            | Code.Conv_Ovf_U8 -> ConvOvfU8
            | Code.Refanyval -> Refanyval (inst.Operand :?> TypeReference)
            | Code.Ckfinite -> Ckfinite
            | Code.Mkrefany -> Mkrefany (inst.Operand :?> TypeReference)
            | Code.Ldtoken -> Ldtoken (inst.Operand :?> IMetadataTokenProvider)
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
            | Code.Leave -> Leave <| brDestCodeBlock ()
            | Code.Stind_I -> StindI unalignedPrefix
            | Code.Conv_U -> ConvU
            | Code.Arglist -> Arglist
            | Code.Ceq -> Ceq
            | Code.Cgt -> Cgt
            | Code.Cgt_Un -> CgtUn
            | Code.Clt -> Clt
            | Code.Clt_Un -> CltUn
            | Code.Ldftn -> Ldftn (inst.Operand :?> MethodReference)
            | Code.Ldvirtftn -> Ldvirtftn (inst.Operand :?> MethodReference)
            | Code.Ldarg -> Ldarg (inst.Operand :?> ParameterDefinition)
            | Code.Ldarga -> Ldarga (inst.Operand :?> ParameterDefinition)
            | Code.Starg -> Starg (inst.Operand :?> ParameterDefinition)
            | Code.Ldloc -> Ldloc (inst.Operand :?> VariableDefinition)
            | Code.Ldloca -> Ldloca (inst.Operand :?> VariableDefinition)
            | Code.Stloc -> Stloc (inst.Operand :?> VariableDefinition)
            | Code.Localloc -> Localloc
            | Code.Endfilter -> Endfilter
            | Code.Unaligned ->
                match unalignedPrefix with
                | Some _ ->
                    failwith "repeated unaligned. prefixes"
                | None ->
                    let op = inst.Operand :?> byte
                    nextInst
                        constrainedPrefix
                        noPrefix
                        readonlyPrefix
                        tailPrefix
                        (Some op)
                        volatilePrefix
            | Code.Volatile ->
                if volatilePrefix then
                    failwith "repeated volatile. prefixes"
                else
                    nextInst
                        constrainedPrefix
                        noPrefix
                        readonlyPrefix
                        tailPrefix
                        unalignedPrefix
                        true
            | Code.Tail ->
                if tailPrefix then
                    failwith "repeated tail. prefixes"
                else
                    nextInst
                        constrainedPrefix
                        noPrefix
                        readonlyPrefix
                        true
                        unalignedPrefix
                        volatilePrefix
            | Code.Initobj -> Initobj (inst.Operand :?> TypeReference)
            | Code.Constrained ->
                match constrainedPrefix with
                | Some _ ->
                    failwith "repeated constrained. prefixes"
                | None ->
                    let op = inst.Operand :?> TypeReference
                    nextInst
                        (Some op)
                        noPrefix
                        readonlyPrefix
                        tailPrefix
                        unalignedPrefix
                        volatilePrefix
            | Code.Cpblk -> Cpblk
            | Code.Initblk -> Initblk unalignedPrefix
            | Code.No ->
                // TODO is it worth doing anything with this?
                let op = inst.Operand :?> byte
                nextInst
                    constrainedPrefix
                    (op ||| noPrefix)
                    readonlyPrefix
                    tailPrefix
                    unalignedPrefix
                    volatilePrefix
            | Code.Rethrow -> Rethrow
            | Code.Sizeof -> Sizeof (inst.Operand :?> TypeReference)
            | Code.Refanytype -> Refanytype
            | Code.Readonly ->
                if readonlyPrefix then
                    failwith "repeated readonly. prefixes"
                else
                    nextInst
                        constrainedPrefix
                        noPrefix
                        true
                        tailPrefix
                        unalignedPrefix
                        volatilePrefix
            | Code.Ldarg_0
            | Code.Ldarg_1
            | Code.Ldarg_2
            | Code.Ldarg_3
            | Code.Ldloc_0
            | Code.Ldloc_1
            | Code.Ldloc_2
            | Code.Ldloc_3
            | Code.Stloc_0
            | Code.Stloc_1
            | Code.Stloc_2
            | Code.Stloc_3
            | Code.Ldarg_S
            | Code.Ldarga_S
            | Code.Starg_S
            | Code.Ldloc_S
            | Code.Ldloca_S
            | Code.Stloc_S
            | Code.Ldc_I4_M1
            | Code.Ldc_I4_0
            | Code.Ldc_I4_1
            | Code.Ldc_I4_2
            | Code.Ldc_I4_3
            | Code.Ldc_I4_4
            | Code.Ldc_I4_5
            | Code.Ldc_I4_6
            | Code.Ldc_I4_7
            | Code.Ldc_I4_8
            | Code.Ldc_I4_S
            | Code.Br_S
            | Code.Brfalse_S
            | Code.Brtrue_S
            | Code.Beq_S
            | Code.Bge_S
            | Code.Bgt_S
            | Code.Ble_S
            | Code.Blt_S
            | Code.Bne_Un_S
            | Code.Bge_Un_S
            | Code.Bgt_Un_S
            | Code.Ble_Un_S
            | Code.Blt_Un_S
            | Code.Leave_S ->
                failwithf "this instruction should have been removed by cecil MethodBodyRocks.SimplifyMacros: %A" inst.OpCode.Code

        [|while !currInstIndex <= lstInstIndex do
            yield nextInst None 0uy false false None false|]
    
    for blockIndex in 0 .. codeBlocks.Length - 1 do
        codeBlocks.[blockIndex].Instructions <- readBlock blockIndex
    codeBlocks

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

