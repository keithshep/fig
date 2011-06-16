module Fig.LLVMCodeGen

open Microsoft.FSharp.Compiler.AbstractIL.IL
open Microsoft.FSharp.Compiler.AbstractIL.ILBinaryReader

open LLVM.Generated.Core
open LLVM.Core

let rec splitAt i xs =
    if i = 0 then
        ([], xs)
    else
        match xs with
        | [] -> failwith "not enough elements for split"
        | x :: xt ->
            let splitFst, splitSnd = splitAt (i - 1) xt
            (x :: splitFst, splitSnd)

let inline ifprintfn depth out fmt =
    for i = 0 to depth - 1 do
        fprintf out "  "
    fprintfn out fmt
let inline iprintfn depth fmt = ifprintfn depth stdout fmt

type AnnoVal =
    | UIntVal of ValueRef
    | IntVal of ValueRef
    with
        member x.Val
            with get () =
                match x with
                | UIntVal v -> v
                | IntVal v -> v

let rec genInstructions
        (bldr : BuilderRef)
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : AnnoVal list)
        (locals : AnnoVal list)
        (blockMap : Map<int, BasicBlockRef>)
        (ilBB : ILBasicBlock)
        (instStack : ValueRef list)
        (depth : int)
        (insts : ILInstr list) =

    match insts with
    | [] ->
        match ilBB.Fallthrough with
        | Some lbl  -> buildBr bldr blockMap.[lbl] |> ignore
        | None      -> ()
    | inst :: instTail ->
        let goNext (instStack : ValueRef list) =
            genInstructions bldr moduleRef methodVal args locals blockMap ilBB instStack depth instTail
        let printInst () = iprintfn depth "%A" inst
        let noImpl () =
            //failwith (sprintf "instruction <<%A>> not implemented" inst)
            iprintfn depth "%A <-- TODO: IMPLEMENT ME" inst
            goNext instStack
        
        match inst with
        // Basic
        | AI_add ->
            // The add instruction adds value2 to value1 and pushes the result
            // on the stack. Overflow is not detected for integral operations
            // (but see add.ovf); floating-point overflow returns +inf or -inf.
            printInst ()
            match instStack with
            | value2 :: value1 :: stackTail ->
                let addResult = buildAdd bldr value1 value2 "tmpAdd"
                goNext (addResult :: stackTail)
            | _ ->
                failwith "instruction stack too low"
        | AI_add_ovf
        | AI_add_ovf_un
        | AI_and
        | AI_div
        | AI_div_un
        | AI_ceq
        | AI_cgt
        | AI_cgt_un
        | AI_clt
        | AI_clt_un
        | AI_conv _      //of ILBasicType
        | AI_conv_ovf _  //of ILBasicType
        | AI_conv_ovf_un _  //of ILBasicType
        | AI_mul
        | AI_mul_ovf
        | AI_mul_ovf_un
        | AI_rem
        | AI_rem_un
        | AI_shl
        | AI_shr
        | AI_shr_un -> noImpl ()
        | AI_sub ->
            // The sub instruction subtracts value2 from value1 and pushes the
            // result on the stack. Overflow is not detected for the integral
            // operations (see sub.ovf); for floating-point operands, sub
            // returns +inf on positive overflow inf on negative overflow, and
            // zero on floating-point underflow.
            printInst ()
            match instStack with
            | value2 :: value1 :: stackTail ->
                let subResult = buildSub bldr value1 value2 "tmpSub"
                goNext (subResult :: stackTail)
            | _ ->
                failwith "instruction stack too low"
        | AI_sub_ovf
        | AI_sub_ovf_un
        | AI_xor
        | AI_or
        | AI_neg
        | AI_not
        | AI_ldnull
        | AI_dup
        | AI_pop
        | AI_ckfinite
        | AI_nop ->
            noImpl ()
        | AI_ldc (basicType, ilConst) ->
            match ilConst with
            | ILConst.I4 i ->
                match basicType with
                | DT_R
                | DT_I1
                | DT_U1
                | DT_I2
                | DT_U2 -> noImpl ()
                | DT_I4 ->
                    printInst ()
                    let constResult = constInt (int32Type ()) (uint64 i) false // TODO correct me!!
                    goNext (constResult :: instStack)
                | DT_U4
                | DT_I8
                | DT_U8
                | DT_R4
                | DT_R8
                | DT_I
                | DT_U
                | DT_REF -> noImpl ()
            | ILConst.I8 i ->
                match basicType with
                | DT_R
                | DT_I1
                | DT_U1
                | DT_I2
                | DT_U2
                | DT_I4
                | DT_U4 -> noImpl ()
                | DT_I8 ->
                    printInst ()
                    let constResult = constInt (int64Type ()) (uint64 i) false // TODO correct me!!
                    goNext (constResult :: instStack)
                | DT_U8
                | DT_R4
                | DT_R8
                | DT_I
                | DT_U
                | DT_REF -> noImpl ()
            | ILConst.R4 r -> noImpl ()
            | ILConst.R8 r -> noImpl ()
        | I_ldarg i ->
            printInst ()
            let name = "tmp_" + getValueName args.[int i].Val
            goNext (buildLoad bldr args.[int i].Val name :: instStack)
        | I_ldarga _    //of uint16
        | I_ldind _ ->  //of ILAlignment * ILVolatility * ILBasicType
            noImpl ()
        | I_ldloc loc ->
            printInst ()
            let loadResult = buildLoad bldr locals.[int loc].Val "tmp"
            goNext (loadResult :: instStack)
        | I_ldloca _ -> noImpl ()   //of uint16
        | I_starg i ->  //of uint16
            printInst ()
            match instStack with
            | stackHead :: stackTail ->
                buildStore bldr stackHead args.[int i].Val |> ignore
                goNext stackTail
            | _ ->
                failwith "instruction stack too low"
        | I_stind _ ->  //of  ILAlignment * ILVolatility * ILBasicType
            noImpl ()
        | I_stloc loc ->
            printInst ()
            match instStack with
            | stackHead :: stackTail ->
                buildStore bldr stackHead locals.[int loc].Val |> ignore
                goNext stackTail
            | _ ->
                failwith "instruction stack too low"
        
        // Control transfer
        | I_br i ->    //of  ILCodeLabel
            buildBr bldr blockMap.[i] |> ignore
        | I_jmp _ ->  //of ILMethodSpec
            noImpl ()
        | I_brcmp (comparisonInstr, codeLabel, fallThroughCodeLabel) ->
            printInst ()
            match instStack with
            //| leftSide :: rightSide :: stackTail ->
            | value2 :: value1 :: stackTail ->
                let isIntCmp = true
                if isIntCmp then
                    
                    let brWith op =
                        //let brTest = buildICmp bldr op leftSide rightSide "brTest"
                        let brTest = buildICmp bldr op value1 value2 "brTest"
                        buildCondBr bldr brTest blockMap.[codeLabel] blockMap.[fallThroughCodeLabel] |> ignore
                    
                    match comparisonInstr with
                    | BI_beq     -> brWith IntPredicate.IntEQ
                    | BI_bge     -> brWith IntPredicate.IntSGE
                    | BI_bge_un  -> brWith IntPredicate.IntUGE
                    | BI_bgt     -> brWith IntPredicate.IntSGT
                    | BI_bgt_un  -> brWith IntPredicate.IntUGT
                    | BI_ble     -> brWith IntPredicate.IntSLE
                    | BI_ble_un  -> brWith IntPredicate.IntULE
                    | BI_blt     -> brWith IntPredicate.IntSLT
                    | BI_blt_un  -> brWith IntPredicate.IntULT
                    | BI_bne_un  -> brWith IntPredicate.IntNE
                    | BI_brfalse -> noImpl ()
                    | BI_brtrue  -> noImpl ()
                else
                     // TODO float comparison else
                    failwith "not yet implemented"
            
            | _ ->
                failwith "instruction stack too low"

        | I_switch (codeLabels, fallThroughCodeLabel) ->    //of (ILCodeLabel list * ILCodeLabel) (* last label is fallthrough *)
            printInst ()
            match instStack with
            | [] -> failwith "empty instruction stack"
            | value :: stackTail ->
                let caseInts =
                    [for i in 0 .. codeLabels.Length - 1 ->
                        constInt (int32Type ()) (uint64 i) false]
                let caseBlocks = [for l in codeLabels -> blockMap.[l]]
                buildSwitchWithCases bldr value (List.zip caseInts caseBlocks) blockMap.[fallThroughCodeLabel]
        
        | I_ret ->
            printInst ()
            match instStack with
            | stackHead :: stackTail ->
                buildRet bldr stackHead |> ignore
            | _ ->
                failwith "instruction stack too low"
         // Method call
        | I_call (tailCall, methodSpec, varArgs) -> // TODO do something w/ tailcall
            iprintfn depth "call: %s::%s GenArgs=%A" methodSpec.MethodRef.mrefParent.trefName methodSpec.Name methodSpec.GenericArgs
            let args, stackTail = splitAt methodSpec.MethodRef.ArgCount instStack
            let args = List.rev args
            let funRef = getNamedFunction moduleRef methodSpec.Name // TODO this naming lookup is too weak (prone to collisions)
            let callResult = buildCall bldr funRef (Array.ofList args) "callResult"
            goNext (callResult :: stackTail)
            //goNext instStack
        | I_callvirt (tailCall, methodSpec, varArgs) ->
            iprintfn depth "callvirt: %s::%s GenArgs=%A <-- TODO"  methodSpec.MethodRef.mrefParent.trefName methodSpec.Name methodSpec.GenericArgs
            // TODO
            goNext instStack
        | I_callconstraint _ //of ILTailcall * ILType * ILMethodSpec * ILVarArgs
        | I_calli _    //of ILTailcall * ILCallingSignature * ILVarArgs
        | I_ldftn _    //of ILMethodSpec
        | I_newobj _   //of ILMethodSpec  * ILVarArgs

        // Exceptions
        | I_throw
        | I_endfinally
        | I_endfilter
        | I_leave _     //of  ILCodeLabel
        | I_rethrow

        // Object instructions
        | I_ldsfld _      //of ILVolatility * ILFieldSpec
        | I_ldfld _       //of ILAlignment * ILVolatility * ILFieldSpec
        | I_ldsflda _     //of ILFieldSpec
        | I_ldflda _      //of ILFieldSpec 
        | I_stsfld _      //of ILVolatility  *  ILFieldSpec
        | I_stfld _ ->    //of ILAlignment * ILVolatility * ILFieldSpec
            noImpl ()
        | I_ldstr s -> noImpl ()
        | I_isinst _      //of ILType
        | I_castclass _   //of ILType
        | I_ldtoken _     //of ILToken
        | I_ldvirtftn _   //of ILMethodSpec

        // Value type instructions
        | I_cpobj _       //of ILType
        | I_initobj _     //of ILType
        | I_ldobj _       //of ILAlignment * ILVolatility * ILType
        | I_stobj _       //of ILAlignment * ILVolatility * ILType
        | I_box _         //of ILType
        | I_unbox _       //of ILType
        | I_unbox_any _   //of ILType
        | I_sizeof _      //of ILType

        // Generalized array instructions. In AbsIL these instructions include
        // both the single-dimensional variants (with ILArrayShape == ILArrayShape.SingleDimensional)
        // and calls to the "special" multi-dimensional "methods" such as
        //   newobj void string[,]::.ctor(int32, int32)
        //   call string string[,]::Get(int32, int32)
        //   call string& string[,]::Address(int32, int32)
        //   call void string[,]::Set(int32, int32,string)
        // The IL reader transforms calls of this form to the corresponding
        // generalized instruction with the corresponding ILArrayShape
        // argument. This is done to simplify the IL and make it more uniform.
        // The IL writer then reverses this when emitting the binary.
        | I_ldelem _      //of ILBasicType
        | I_stelem _      //of ILBasicType
        | I_ldelema _     //of ILReadonly * ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
        | I_ldelem_any _  //of ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
        | I_stelem_any _  //of ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
        | I_newarr _      //of ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
        | I_ldlen

        // "System.TypedReference" related instructions: almost
        // no languages produce these, though they do occur in mscorlib.dll
        // System.TypedReference represents a pair of a type and a byref-pointer
        // to a value of that type. 
        | I_mkrefany _    //of ILType
        | I_refanytype
        | I_refanyval _   //of ILType
        
        // Debug-specific 
        // I_seqpoint is a fake instruction to represent a sequence point:
        // the next instruction starts the execution of the
        // statement covered by the given range - this is a
        // dummy instruction and is not emitted
        | I_break
        | I_seqpoint _ //of ILSourceMarker

        // Varargs - C++ only
        | I_arglist

        // Local aggregates, i.e. stack allocated data (alloca) : C++ only
        | I_localloc
        | I_cpblk _ //of ILAlignment * ILVolatility
        | I_initblk _ //of ILAlignment  * ILVolatility

        // EXTENSIONS, e.g. MS-ILX
        | EI_ilzero _ //of ILType
        | EI_ldlen_multi _      //of int32 * int32
        | I_other _ -> noImpl ()   //of IlxExtensionInstr

let genBasicBlock
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : AnnoVal list)
        (locals : AnnoVal list)
        (blockMap : Map<int, BasicBlockRef>)
        (depth : int)
        (ilBB : ILBasicBlock) =
    match ilBB.Fallthrough with
    | Some lbl  -> iprintfn depth "basicblock (%i, fallthrough=%i)" ilBB.Label lbl
    | None      -> iprintfn depth "basicblock (%i)" ilBB.Label

    use bldr = new Builder(blockMap.[ilBB.Label])
    genInstructions bldr moduleRef methodVal args locals blockMap ilBB [] (depth + 1) (List.ofArray ilBB.Instructions)

let rec genCode
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : AnnoVal list)
        (locals : AnnoVal list)
        (blockMap : Map<int, BasicBlockRef>)
        (depth : int)
        (c : ILCode) =

    let genNextCode = genCode moduleRef methodVal args locals blockMap
    
    iprintfn depth "code"
    match c with
    | ILBasicBlock bb -> genBasicBlock moduleRef methodVal args locals blockMap (depth + 1) bb
    | GroupBlock (debugMappings, codes) ->
        iprintfn depth "groupblock"
        for c in codes do
            genNextCode (depth + 1) c
    | RestrictBlock (codeLabels, code) ->
        iprintfn depth "restrictblock"
        genNextCode (depth + 1) code
    | TryBlock (tCode, exceptionBlock) ->
        iprintfn (depth + 1) "tryBlock"
        genNextCode (depth + 2) tCode
        match exceptionBlock with
        | FaultBlock code ->
            iprintfn (depth + 1) "faultBlock"
            genNextCode (depth + 2) code
        | FinallyBlock ilCode ->
            iprintfn (depth + 1) "finallyBlock"
            genNextCode (depth + 2) ilCode
        | FilterCatchBlock filterCatchList ->
            iprintfn (depth + 1) "filterCatchBlock TODO"

let genAlloca (bldr : BuilderRef) (depth : int) (t : ILType) (name : string) =
    match t with
    | ILType.Void
    | ILType.Array _ -> failwith "unsuported local type"
    | ILType.Value typeSpec ->
        match typeSpec.tspecTypeRef.trefName with
        | "System.Int32"  ->
            IntVal <| buildAlloca bldr (int32Type ()) (name + "Alloca")
        | "System.UInt32" ->
            UIntVal <| buildAlloca bldr (int32Type ()) (name + "Alloca")
        | "System.Int64"  ->
            IntVal <| buildAlloca bldr (int64Type ()) (name + "Alloca")
        | "System.UInt64" ->
            UIntVal <| buildAlloca bldr (int64Type ()) (name + "Alloca")
        | "System.SByte"  ->
            IntVal <| buildAlloca bldr (int8Type ()) (name + "Alloca")
        | _ ->
            failwith (sprintf "unknown value type %A" typeSpec)
    | ILType.Boxed _
    | ILType.Ptr _
    | ILType.Byref _
    | ILType.FunctionPointer _
    | ILType.TypeVar _
    | ILType.Modified _ -> failwith "unsuported local type"

let genLocal (bldr : BuilderRef) (depth : int) (l : ILLocal) =
    let tyStr =
        match l.Type with
        | ILType.Void -> "void"
        | ILType.Array (ilArrayShape, ilType) -> "array"
        | ILType.Value typeSpec ->
            match typeSpec.tspecTypeRef.trefName with
            | "System.Int32" ->
                "int32 value"
            | "System.UInt32" ->
                "uint32 value"
            | "System.Int64" ->
                "int64 value"
            | "System.UInt64" ->
                "uint64 value"
            | "System.SByte" ->
                "int8 value"
            | _ -> failwith (sprintf "unknown value type %A" typeSpec)
        | ILType.Boxed ilTypeSpec -> "boxed"
        | ILType.Ptr ilType -> "ptr"
        | ILType.Byref ilType -> "byref"
        | ILType.FunctionPointer ilCallingSignature -> "funPtr"
        | ILType.TypeVar ui -> "typevar"
        | ILType.Modified (required, modifierRef, ilType) -> "modified"
    iprintfn depth "%s" tyStr
    
    genAlloca bldr depth l.Type "local"

let genParam (bldr : BuilderRef) (depth : int) (p : ILParameter) =
    genAlloca bldr depth p.Type (match p.Name with Some n -> n | None -> "param")

let addBlockDecs (methodVal : ValueRef) (c : ILCode) =
    let rec go (c : ILCode) =
        match c with
        | ILBasicBlock bb -> [(bb.Label, appendBasicBlock methodVal ("block_" + string bb.Label))]
        | GroupBlock (debugMappings, codes) -> List.collect go codes
        | RestrictBlock (codeLabels, code) -> go code
        | TryBlock (tCode, exceptionBlock) -> failwith "TryBlock not yet implemented"

    go c

let genMethodBody (moduleRef : ModuleRef) (methodVal : ValueRef) (depth : int) (md : ILMethodDef) (mb : ILMethodBody) =
    // create the entry block
    use bldr = new Builder(appendBasicBlock methodVal "entry")

    let args = List.map (genParam bldr (depth + 2)) md.Parameters
    for i = 0 to args.Length - 1 do
        buildStore bldr (getParam methodVal (uint32 i)) args.[i].Val |> ignore
    
    iprintfn (depth + 1) "locals"
    let locals = List.map (genLocal bldr (depth + 2)) mb.Locals
    let blockDecs = addBlockDecs methodVal mb.Code

    match blockDecs with
    | [] -> failwith ("empty method body: " + md.Name)
    | (_, fstBlockDec) :: _ ->
        buildBr bldr fstBlockDec |> ignore
        genCode moduleRef methodVal args locals (Map.ofList blockDecs) (depth + 1) mb.Code

let paramType (param : ILParameter) =
    match param.Type with
    | ILType.Void -> failwith "void param"
    | ILType.Array (ilArrayShape, ilType) -> failwith "array param"
    | ILType.Value typeSpec ->
        match typeSpec.tspecTypeRef.trefName with
        | "System.Int32"
        | "System.UInt32"   -> int32Type ()
        | "System.Int64"
        | "System.UInt64"   -> int64Type ()
        | "System.SByte"    -> int8Type ()
        | "System.Boolean"  -> int1Type ()
        | _ -> failwith (sprintf "unknown param value type %A" typeSpec)
    | ILType.Boxed ilTypeSpec -> failwith "boxed param"
    | ILType.Ptr ilType -> failwith "ptr param"
    | ILType.Byref ilType -> failwith "byref param"
    | ILType.FunctionPointer ilCallingSignature -> failwith "funPtr param"
    | ILType.TypeVar ui -> failwith "typevar param"
    | ILType.Modified (required, modifierRef, ilType) -> failwith "modified param"

let returnType (retTy : ILReturn) =
    match retTy.Type with
    | ILType.Void -> voidType ()
    | ILType.Array (ilArrayShape, ilType) -> failwith "array return"
    | ILType.Value typeSpec ->
        match typeSpec.tspecTypeRef.trefName with
        | "System.Int32"
        | "System.UInt32"   -> int32Type ()
        | "System.Int64"
        | "System.UInt64"   -> int64Type ()
        | "System.SByte"    -> int8Type ()
        | "System.Boolean"  -> int1Type ()
        | _ -> failwith (sprintf "unknown return value type %A" typeSpec)
    | ILType.Boxed ilTypeSpec -> failwith "boxed return"
    | ILType.Ptr ilType -> failwith "ptr return"
    | ILType.Byref ilType -> failwith "byref return"
    | ILType.FunctionPointer ilCallingSignature -> failwith "funPtr return"
    | ILType.TypeVar ui -> failwith "typevar return"
    | ILType.Modified (required, modifierRef, ilType) -> failwith "modified return"

let genMethodDef (moduleRef : ModuleRef) (depth : int) (md : ILMethodDef) =
    let paramTys = [|for p in md.Parameters -> paramType p|]
    let retTy = returnType md.Return
    let funcTy = functionType retTy paramTys
    iprintfn depth "%s" md.Name
    match md.mdBody.Contents with
    | MethodBody.IL mb ->
        let fn = addFunction moduleRef md.Name funcTy
        for i = 0 to md.Parameters.Length - 1 do
            match md.Parameters.[i].Name with
            | Some name -> setValueName (getParam fn (uint32 i)) name |> ignore
            | None -> setValueName (getParam fn (uint32 i)) ("arg" + string i) |> ignore

        genMethodBody moduleRef fn depth md mb
    | MethodBody.PInvoke pInvokeMethod -> iprintfn depth "PInvoke: %s" pInvokeMethod.Name
    | MethodBody.Abstract -> iprintfn (depth + 1) "abstract"
    | MethodBody.Native -> iprintfn (depth + 1) "native"

let rec genTypeDef (moduleRef : ModuleRef) (depth : int) (td : ILTypeDef) =
    iprintfn depth "%A %s" td.tdKind td.Name
    if not (Seq.isEmpty td.NestedTypes) then
        iprintfn (depth + 1) "Nested Type Defs:"
        Seq.iter (genTypeDef moduleRef (depth + 2)) td.NestedTypes
    if not (Seq.isEmpty td.Methods) then
        iprintfn (depth + 1) "Nested Method Defs:"
        Seq.iter (genMethodDef moduleRef (depth + 2)) td.Methods

let genTypeDefs (moduleRef : ModuleRef) (typeDefs : ILTypeDefs) =
    Seq.iter (genTypeDef moduleRef 0) typeDefs

