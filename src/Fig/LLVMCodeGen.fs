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

let rec genInstructions
        (bldr : BuilderRef)
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : ValueRef list)
        (locals : ValueRef list)
        (funMap : Map<string, Map<(ILType * string * (ILType list)), ValueRef>>)
        (blockMap : Map<int, BasicBlockRef>)
        (ilBB : ILBasicBlock)
        (instStack : ValueRef list)
        (insts : ILInstr list) =

    match insts with
    | [] ->
        match ilBB.Fallthrough with
        | Some lbl  -> buildBr bldr blockMap.[lbl] |> ignore
        | None      -> ()
    | inst :: instTail ->
        let goNext (instStack : ValueRef list) =
            genInstructions bldr moduleRef methodVal args locals funMap blockMap ilBB instStack instTail
        let noImpl () = failwith (sprintf "instruction <<%A>> not implemented" inst)
        
        match inst with
        // Basic
        | AI_add ->
            // The add instruction adds value2 to value1 and pushes the result
            // on the stack. Overflow is not detected for integral operations
            // (but see add.ovf); floating-point overflow returns +inf or -inf.
            match instStack with
            | value2 :: value1 :: stackTail ->
                let addResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFAdd bldr value1 value2 "tmpFAdd"
                    | TypeKind.IntegerTypeKind ->
                        buildAdd bldr value1 value2 "tmpAdd"
                    | ty ->
                        failwith (sprintf "don't know how to add type: %A" ty)
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
        | AI_conv_ovf_un _ -> noImpl ()  //of ILBasicType
        | AI_mul ->
            // The mul instruction multiplies value1 by value2 and pushes
            // the result on the stack. Integral operations silently 
            // truncate the upper bits on overflow (see mul.ovf).
            // TODO: For floating-point types, 0 × infinity = NaN.
            match instStack with
            | value2 :: value1 :: stackTail ->
                let mulResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFMul bldr value1 value2 "tmpFMul"
                    | TypeKind.IntegerTypeKind ->
                        buildMul bldr value1 value2 "tmpMul"
                    | ty ->
                        failwith (sprintf "don't know how to multiply type: %A" ty)
                goNext (mulResult :: stackTail)
            | _ ->
                failwith "instruction stack too low"
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
            match instStack with
            | value2 :: value1 :: stackTail ->
                let subResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFSub bldr value1 value2 "tmpFSub"
                    | TypeKind.IntegerTypeKind ->
                        buildSub bldr value1 value2 "tmpSub"
                    | ty ->
                        failwith (sprintf "don't know how to sub type: %A" ty)
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
                    let constResult = constInt (int64Type ()) (uint64 i) false // TODO correct me!!
                    goNext (constResult :: instStack)
                | DT_U8
                | DT_R4
                | DT_R8
                | DT_I
                | DT_U
                | DT_REF -> noImpl ()
            | ILConst.R4 r -> noImpl ()
            | ILConst.R8 r ->
                match basicType with
                | DT_R
                | DT_I1
                | DT_U1
                | DT_I2
                | DT_U2
                | DT_I4
                | DT_U4
                | DT_I8
                | DT_U8
                | DT_R4 -> noImpl ()
                | DT_R8 ->
                    let constResult = constReal (doubleType ()) r
                    goNext (constResult :: instStack)
                | DT_I
                | DT_U
                | DT_REF -> noImpl ()
        | I_ldarg i ->
            let name = "tmp_" + getValueName args.[int i]
            goNext (buildLoad bldr args.[int i] name :: instStack)
        | I_ldarga _    //of uint16
        | I_ldind _ ->  //of ILAlignment * ILVolatility * ILBasicType
            noImpl ()
        | I_ldloc loc ->
            let loadResult = buildLoad bldr locals.[int loc] "tmp"
            goNext (loadResult :: instStack)
        | I_ldloca _ -> noImpl ()   //of uint16
        | I_starg i ->  //of uint16
            match instStack with
            | stackHead :: stackTail ->
                buildStore bldr stackHead args.[int i] |> ignore
                goNext stackTail
            | _ ->
                failwith "instruction stack too low"
        | I_stind _ ->  //of  ILAlignment * ILVolatility * ILBasicType
            noImpl ()
        | I_stloc loc ->
            match instStack with
            | stackHead :: stackTail ->
                buildStore bldr stackHead locals.[int loc] |> ignore
                goNext stackTail
            | _ ->
                failwith "instruction stack too low"
        
        // Control transfer
        | I_br i ->    //of  ILCodeLabel
            buildBr bldr blockMap.[i] |> ignore
        | I_jmp _ ->  //of ILMethodSpec
            noImpl ()
        | I_brcmp (comparisonInstr, codeLabel, fallThroughCodeLabel) ->
            match instStack with
            //| leftSide :: rightSide :: stackTail ->
            | value2 :: value1 :: stackTail ->
                let isIntCmp = true
                match getTypeKind <| typeOf value1 with
                | TypeKind.IntegerTypeKind ->
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
                | ty ->
                    failwith (sprintf "don't know how to compare type: %A" ty)
            
            | _ ->
                failwith "instruction stack too low"

        | I_switch (codeLabels, fallThroughCodeLabel) ->    //of (ILCodeLabel list * ILCodeLabel) (* last label is fallthrough *)
            match instStack with
            | [] -> failwith "empty instruction stack"
            | value :: stackTail ->
                let caseInts =
                    [for i in 0 .. codeLabels.Length - 1 ->
                        constInt (int32Type ()) (uint64 i) false]
                let caseBlocks = [for l in codeLabels -> blockMap.[l]]
                buildSwitchWithCases bldr value (List.zip caseInts caseBlocks) blockMap.[fallThroughCodeLabel]
        
        | I_ret ->
            match instStack with
            | stackHead :: stackTail ->
                buildRet bldr stackHead |> ignore
            | _ ->
                failwith "instruction stack too low"
         // Method call
        | I_call (tailCall, methodSpec, varArgs) -> // TODO do something w/ tailcall
            // look up the corresponding LLVM function
            let enclosingName = methodSpec.EnclosingType.BasicQualifiedName
            let argTypes = methodSpec.FormalArgTypes
            let retType = methodSpec.FormalReturnType
            let name = methodSpec.Name
            let funRef = funMap.[enclosingName].[(retType, name, argTypes)]
            
            let args, stackTail = splitAt methodSpec.MethodRef.ArgCount instStack
            let args = List.rev args
            let callResult = buildCall bldr funRef (Array.ofList args) "callResult"
            
            match tailCall with
            | Normalcall ->
                goNext (callResult :: stackTail)
            | Tailcall ->
                // TODO confirm with CIL docs that tail call includes implicit return
                setTailCall callResult true
                buildRet bldr callResult |> ignore
                goNext stackTail // TODO can probably dump this
            
            //goNext instStack
        | I_callvirt _ // (tailCall, methodSpec, varArgs) ->
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
        | I_stfld _       //of ILAlignment * ILVolatility * ILFieldSpec
        | I_ldstr _       //of string
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
        (args : ValueRef list)
        (locals : ValueRef list)
        (funMap : Map<string, Map<(ILType * string * (ILType list)), ValueRef>>)
        (blockMap : Map<int, BasicBlockRef>)
        (ilBB : ILBasicBlock) =
    use bldr = new Builder(blockMap.[ilBB.Label])
    genInstructions bldr moduleRef methodVal args locals funMap blockMap ilBB [] (List.ofArray ilBB.Instructions)

let rec genCode
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : ValueRef list)
        (locals : ValueRef list)
        (funMap : Map<string, Map<(ILType * string * (ILType list)), ValueRef>>)
        (blockMap : Map<int, BasicBlockRef>)
        (c : ILCode) =

    let genNextCode = genCode moduleRef methodVal args locals funMap blockMap
    
    match c with
    | ILBasicBlock bb -> genBasicBlock moduleRef methodVal args locals funMap blockMap bb
    | GroupBlock (debugMappings, codes) ->
        for c in codes do
            genNextCode c
    | RestrictBlock (codeLabels, code) ->
        genNextCode code
    | TryBlock (tCode, exceptionBlock) ->
        failwith "try block not implemented"
//        genNextCode (depth + 2) tCode
//        match exceptionBlock with
//        | FaultBlock code ->
//            genNextCode (depth + 2) code
//        | FinallyBlock ilCode ->
//            genNextCode (depth + 2) ilCode
//        | FilterCatchBlock filterCatchList ->
//            iprintfn (depth + 1) "filterCatchBlock TODO"

let toLLVMType (ty : ILType) =
    match ty with
    | ILType.Void -> voidType ()
    | ILType.Array (ilArrayShape, ilType) -> failwith "array type"
    | ILType.Value typeSpec ->
        match typeSpec.tspecTypeRef.trefName with
        | "System.Int32"
        | "System.UInt32"   -> int32Type ()
        | "System.Int64"
        | "System.UInt64"   -> int64Type ()
        | "System.SByte"    -> int8Type ()
        
        // TODO compiler seems to be generating boolean as I4 but the CIL docs
        // say that a single byte should be used to represent a boolean
        | "System.Boolean"  -> int32Type ()
        | "System.Double"   -> doubleType ()
        | tyStr -> failwith ("unknown value type: " + tyStr)
    | ILType.Boxed ilTypeSpec -> failwith "boxed type"
    | ILType.Ptr ilType -> failwith "ptr type"
    | ILType.Byref ilType -> failwith "byref type"
    | ILType.FunctionPointer ilCallingSignature -> failwith "funPtr type"
    | ILType.TypeVar ui -> failwith "typevar type"
    | ILType.Modified (required, modifierRef, ilType) -> failwith "modified type"

let genAlloca (bldr : BuilderRef) (t : ILType) (name : string) =
    buildAlloca bldr (toLLVMType t) (name + "Alloca")

let genLocal (bldr : BuilderRef) (l : ILLocal) =
    genAlloca bldr l.Type "local"

let genParam (bldr : BuilderRef) (p : ILParameter) =
    genAlloca bldr p.Type (match p.Name with Some n -> n | None -> "param")

let addBlockDecs (methodVal : ValueRef) (c : ILCode) =
    let rec go (c : ILCode) =
        match c with
        | ILBasicBlock bb -> [(bb.Label, appendBasicBlock methodVal ("block_" + string bb.Label))]
        | GroupBlock (debugMappings, codes) -> List.collect go codes
        | RestrictBlock (codeLabels, code) -> go code
        | TryBlock (tCode, exceptionBlock) -> failwith "TryBlock not yet implemented"

    go c

let genMethodBody
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (funMap : Map<string, Map<(ILType * string * (ILType list)), ValueRef>>)
        (md : ILMethodDef)
        (mb : ILMethodBody) =
    // create the entry block
    use bldr = new Builder(appendBasicBlock methodVal "entry")

    let args = List.map (genParam bldr) md.Parameters
    for i = 0 to args.Length - 1 do
        buildStore bldr (getParam methodVal (uint32 i)) args.[i] |> ignore
    
    let locals = List.map (genLocal bldr) mb.Locals
    let blockDecs = addBlockDecs methodVal mb.Code

    match blockDecs with
    | [] -> failwith ("empty method body: " + md.Name)
    | (_, fstBlockDec) :: _ ->
        buildBr bldr fstBlockDec |> ignore
        genCode moduleRef methodVal args locals funMap (Map.ofList blockDecs) mb.Code

let genMethodDef
        (moduleRef : ModuleRef)
        (funMap : Map<string, Map<(ILType * string * (ILType list)), ValueRef>>)
        (md : ILMethodDef) =
    match md.mdBody.Contents with
    | MethodBody.IL mb ->
        let fn = getNamedFunction moduleRef md.Name
        genMethodBody moduleRef fn funMap md mb
    | MethodBody.PInvoke pInvokeMethod -> failwith "PInvoke body"
    | MethodBody.Abstract -> failwith "abstract body"
    | MethodBody.Native -> failwith "native body"

let rec genTypeDef
        (moduleRef : ModuleRef)
        (funMap : Map<string, Map<(ILType * string * (ILType list)), ValueRef>>)
        (td : ILTypeDef) =
    Seq.iter (genTypeDef moduleRef funMap) td.NestedTypes
    Seq.iter (genMethodDef moduleRef funMap) td.Methods

let declareMethodDef (moduleRef : ModuleRef) (md : ILMethodDef) =
    let paramTys = [|for p in md.Parameters -> toLLVMType p.Type|]
    let retTy = toLLVMType md.Return.Type
    let funcTy = functionType retTy paramTys
    match md.mdBody.Contents with
    | MethodBody.IL mb ->
        let fn = addFunction moduleRef md.Name funcTy
        for i = 0 to md.Parameters.Length - 1 do
            match md.Parameters.[i].Name with
            | Some name -> setValueName (getParam fn (uint32 i)) name |> ignore
            | None -> setValueName (getParam fn (uint32 i)) ("arg" + string i) |> ignore
        (md.Return.Type, md.Name, [for p in md.Parameters -> p.Type]), fn
    | MethodBody.PInvoke _
    | MethodBody.Abstract
    | MethodBody.Native -> failwith "unsupported method body type"

let rec declareTypeDef (moduleRef : ModuleRef) (td : ILTypeDef) =
    let nestedDecs = List.concat [for t in td.NestedTypes -> declareTypeDef moduleRef t]
    let methodDecs = [for m in td.Methods -> declareMethodDef moduleRef m]
    (td.Name, Map.ofList methodDecs) :: nestedDecs

let genTypeDefs (moduleRef : ModuleRef) (typeDefs : ILTypeDefs) =
    let funMap = Map.ofList <| List.concat [for t in typeDefs -> declareTypeDef moduleRef t]
    Seq.iter (genTypeDef moduleRef funMap) typeDefs

