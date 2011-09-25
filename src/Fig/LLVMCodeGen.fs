module Fig.LLVMCodeGen

open Fig.CecilExt

open Mono.Cecil
open Mono.Cecil.Cil

open LLVM.Generated.Core
open LLVM.Core

let nullableAsOption (n : System.Nullable<'a>) =
    if n.HasValue then
        Some n.Value
    else
        None

type FunMap = Map<string, Map<string , ValueRef>>

type TypeHandleRef with
    member x.ResolvedType with get () = resolveTypeHandle x

(*
type JointTypeDef (td : TypeDefinition, tyHandle : TypeHandleRef) =
    member x.CILType with get() = td
    member x.LLVMType with get() = resolveTypeHandle tyHandle
    member x.LLVMTypeHandle with get() = tyHandle
*)

let rec toLLVMType (typeHandles : Map<string, TypeHandleRef>) (ty : TypeReference) =
    let noImpl () = failwithf "no impl for %A type yet" ty.MetadataType
    
    match toSaferType ty with
    | Void -> voidType ()

    // TODO compiler seems to be generating boolean as I4 but the CIL docs
    // say that a single byte should be used to represent a boolean
    | Boolean -> int32Type ()
    | Char -> noImpl ()
    | SByte
    | Byte -> int8Type ()
    | Int16
    | UInt16 -> noImpl ()
    | Int32
    | UInt32 -> int32Type ()
    | Int64
    | UInt64 -> int64Type ()
    | Single -> noImpl ()
    | Double -> doubleType ()
    | String
    | Pointer _ // PointerType
    | ByReference _ // ByReferenceType
    | ValueType _ // TypeReference
    | Class _ // TypeReference
    | Var _ -> // GenericParameter
        noImpl ()
    | Array arrTy ->
        if arrTy.Rank = 1 then
            let dim0 = arrTy.Dimensions.[0]
            match nullableAsOption dim0.LowerBound, nullableAsOption dim0.UpperBound with
            | (Some 0, None) -> //(0, null) ->
                // LLVM docs say:
                // "... 'variable sized array' addressing can be implemented in LLVM
                // with a zero length array type". So, we implement this as a struct
                // which contains a length element and an array element
                let elemTy = toLLVMType typeHandles arrTy.ElementType
                let basicArrTy = pointerType (arrayType elemTy 0u) 0u
                // FIXME array len should correspond to "native unsigned int" not int32
                pointerType (structType [|int32Type (); basicArrTy|] false) 0u
            | _ ->
                failwith "dont know how to deal with given array shape yet"
        else
            failwithf "arrays of rank %i not yet implemented" arrTy.Rank
    | GenericInstance _ // GenericInstanceType
    | TypedByReference
    | IntPtr
    | UIntPtr
    | FunctionPointer _ // FunctionPointerType
    | Object
    | MVar _ // GenericParameter
    | RequiredModifier _ // RequiredModifierType
    | OptionalModifier _ // OptionalModifierType
    | Sentinel _ // SentinelType
    | Pinned _ -> // PinnedType
        noImpl ()

let rec genInstructions
        (bldr : BuilderRef)
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : ValueRef array)
        (locals : ValueRef array)
        (typeHandles : Map<string, TypeHandleRef>)
        (funMap : FunMap)
        (blockMap : Map<int, BasicBlockRef>)
        (ilBB : BasicBlock)
        (instStack : ValueRef list)
        (insts : AnnotatedInstruction list) =

    match insts with
    | [] -> ()
    | inst :: instTail ->
        let goNext (instStack : ValueRef list) =
            genInstructions bldr moduleRef methodVal args locals typeHandles funMap blockMap ilBB instStack instTail
        let noImpl () = failwith (sprintf "instruction <<%A>> not implemented" inst)

        match inst.Instruction with
        | Add ->
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
        | _ -> noImpl ()
        (*
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
        
        // call* instructions all start with bool "tail." prefix indicator.
        // See: EMCA-335 Partition III 2.4
        | Call of bool * MethodReference
        | Calli of bool * CallSite
        
        // callvirt can also take a "constrained." prefix
        // See: EMCA-335 Partition III 2.1
        | Callvirt of bool * TypeReference option * MethodReference
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
        
        // ldind* instructions hold a byte option for the "unaligned." prefix
        // and a bool for the "volatile." prefix
        // See: EMCA-335 Partition III 2.5 & 2.6
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
        | Ldloc of VariableDefinition
        | Ldloca of VariableDefinition
        | Ldnull
    
        // Ldobj instruction hold a byte option for the "unaligned." prefix
        // and a bool for the "volatile." prefix
        // See: EMCA-335 Partition III 2.5 & 2.6
        | Ldobj of byte option * bool * TypeReference
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
        
        // Stind* instructions hold a byte option for the "unaligned." prefix
        // and a bool for the "volatile." prefix
        // See: EMCA-335 Partition III 2.5 & 2.6
        | StindRef of byte option * bool
        | StindI1 of byte option * bool
        | StindI2 of byte option * bool
        | StindI4 of byte option * bool
        | StindI8 of byte option * bool
        | StindR4 of byte option * bool
        | StindR8 of byte option * bool
        | Stloc of VariableDefinition
        | Sub
        | Switch of CodeBlock array
        | Xor
        | Castclass of TypeReference
        | Isinst of TypeReference
        | ConvRUn
        | Unbox of TypeReference
        | Throw
    
        // ldfld*/stfld instructions hold a byte option for the "unaligned." prefix
        // and a bool for the "volatile." prefix
        // See: EMCA-335 Partition III 2.5 & 2.6
        | Ldfld of byte option * bool * FieldReference
        | Ldflda of byte option * bool * FieldReference
        | Stfld of byte option * bool * FieldReference
        
        // ldsfld*/stsfld instructions hold a bool indicator for the "volatile." prefix
        | Ldsfld of bool * FieldReference
        | Ldsflda of bool * FieldReference
        | Stsfld of bool * FieldReference
        
        // stobj instruction holds a byte option for the "unaligned." prefix
        // and a bool for the "volatile." prefix
        // See: EMCA-335 Partition III 2.5 & 2.6
        | Stobj of byte option * bool * TypeReference
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
        
        // ldelema instruction holds a bool to indicate that it is preceded by a
        // "readonly." prefix
        // See: EMCA-335 Partition III 2.3
        | Ldelema of bool * TypeReference
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
    
        // stindi instructions hold a byte option for the "unaligned." prefix
        // and a bool for the "volatile." prefix
        // See: EMCA-335 Partition III 2.5 & 2.6
        | StindI of byte option * bool
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
    
        // initblk instructions hold a byte option for the "unaligned." prefix
        // and a bool for the "volatile." prefix
        // See: EMCA-335 Partition III 2.5 & 2.6
        | Initblk of byte option * bool
        | Rethrow
        | Sizeof of TypeReference
        | Refanytype
        *)

(*
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
        | AI_and -> noImpl ()
        | AI_div ->
            match instStack with
            | value2 :: value1 :: stackTail ->
                let divResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFDiv bldr value1 value2 "tmpFDiv"
                    | TypeKind.IntegerTypeKind ->
                        buildSDiv bldr value1 value2 "tmpDiv"
                    | ty ->
                        failwith (sprintf "don't know how to div type: %A" ty)
                goNext (divResult :: stackTail)
            | _ ->
                failwith "instruction stack too low"
        | AI_div_un
        | AI_ceq
        | AI_cgt
        | AI_cgt_un
        | AI_clt
        | AI_clt_un -> noImpl ()
        | AI_conv basicType -> //of ILBasicType
            match basicType with
            | DT_R
            | DT_I1
            | DT_U1
            | DT_I2
            | DT_U2 -> noImpl ()
            | DT_I4 ->
                match instStack with
                | stackHead :: stackTail ->
                    let headType = typeOf stackHead
                    match getTypeKind headType with
                    | TypeKind.IntegerTypeKind ->
                        if getIntTypeWidth headType = 32u then
                            goNext instStack
                        else
                            failwith "not 32u"
                    | _ ->
                        failwith "not an int kind"
                | _ ->
                    failwith "instruction stack too low"
            | DT_U4
            | DT_I8
            | DT_U8
            | DT_R4 -> noImpl ()
            | DT_R8 ->
                match instStack with
                | stackHead :: stackTail ->
                    let headType = typeOf stackHead
                    match getTypeKind headType with
                    | TypeKind.IntegerTypeKind ->
                        if getIntTypeWidth headType = 32u then
                            // FIXME don't really know if it's signed or unsigned here
                            let convVal = buildSIToFP bldr stackHead (doubleType ()) "convVal"
                            goNext (convVal :: stackTail)
                        else
                            failwith "not 32u"
                    | _ ->
                        failwith "not an int kind"
                | _ ->
                    failwith "instruction stack too low"
            | DT_I
            | DT_U
            | DT_REF -> noImpl ()
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
                    [|for i in 0 .. codeLabels.Length - 1 ->
                        constInt (int32Type ()) (uint64 i) false|]
                let caseBlocks = [|for l in codeLabels -> blockMap.[l]|]
                buildSwitchWithCases bldr value (Array.zip caseInts caseBlocks) blockMap.[fallThroughCodeLabel]
        
        | I_ret ->
            // TODO confirm void funs are [] and non-void are not
            match instStack with
            | [] -> buildRetVoid bldr |> ignore
            | stackHead :: stackTail -> buildRet bldr stackHead |> ignore
         // Method call
        | I_call (tailCall, methodSpec, varArgs) ->
            // look up the corresponding LLVM function
            let enclosingName = methodSpec.EnclosingType.BasicQualifiedName
            let argTypes = methodSpec.FormalArgTypes
            let retType = methodSpec.FormalReturnType
            let name = methodSpec.Name
            if enclosingName = "System.Object" && name = ".ctor" then
                //TODO stop ignoring object calls
                goNext instStack.Tail
            else
                let funRef = funMap.[enclosingName].[(retType, name, argTypes)]

                let argCount =
                    match methodSpec.CallingConv.ThisConv with
                    | ILThisConvention.Instance ->
                        methodSpec.MethodRef.ArgCount + 1
                    | ILThisConvention.InstanceExplicit ->
                        failwith "instance explicit not implemented"
                    | ILThisConvention.Static ->
                        methodSpec.MethodRef.ArgCount
                let args, stackTail = splitAt methodSpec.MethodRef.ArgCount instStack
                let args = List.rev args
                let callResult = buildCall bldr funRef (Array.ofList args) "callResult" // FIXME void results should not add to stack!!
                
                match tailCall with
                | Normalcall ->
                    goNext (callResult :: stackTail)
                | Tailcall ->
                    // TODO confirm with CIL docs that tail call includes implicit return
                    setTailCall callResult true
                    buildRet bldr callResult |> ignore
                    goNext stackTail // TODO can probably dump this
            
        | I_callvirt _ // (tailCall, methodSpec, varArgs) ->
        | I_callconstraint _ //of ILTailcall * ILType * ILMethodSpec * ILVarArgs
        | I_calli _    //of ILTailcall * ILCallingSignature * ILVarArgs
        | I_ldftn _ -> noImpl ()   //of ILMethodSpec
        | I_newobj (methodSpec, varArgs) -> //of ILMethodSpec  * ILVarArgs
            // TODO implement GC
            // FIXME naming is all screwed up! fix it
            //let enclosingName = methodSpec.EnclosingType.BasicQualifiedName
            let enclosingName = methodSpec.EnclosingType.TypeRef.Name
            let argTypes = methodSpec.FormalArgTypes
            let retType = methodSpec.FormalReturnType
            let name = methodSpec.Name
            if name <> ".ctor" then
                failwith "expected a .ctor here"
            else
                let funRef = funMap.[enclosingName].[(retType, name, argTypes)]
                let llvmTy = typeHandles.[enclosingName].LLVMType
                let newObj = buildMalloc bldr llvmTy ("new" + enclosingName)
                let argCount = methodSpec.MethodRef.ArgCount + 1 // +1 for self
                let args, stackTail = splitAt methodSpec.MethodRef.ArgCount instStack
                let args = newObj :: List.rev args
                buildCall bldr funRef (Array.ofList args) "" |> ignore
                goNext (newObj :: stackTail)
        // Exceptions
        | I_throw
        | I_endfinally
        | I_endfilter
        | I_leave _     //of  ILCodeLabel
        | I_rethrow

        // Object instructions
        | I_ldsfld _ -> noImpl () //of ILVolatility * ILFieldSpec
        | I_ldfld (align, vol, field) -> //of ILAlignment * ILVolatility * ILFieldSpec
            match instStack with
            | [] -> failwith "empty instruction stack"
            | selfPtr :: stackTail ->
                // TODO alignment and volitility
                let selfJoint = typeHandles.[field.EnclosingTypeRef.Name]
                let cilFields = selfJoint.CILType.Fields.AsList
                let fieldIndex = List.findIndex (fun (f : ILFieldDef) -> f.Name = field.Name) cilFields

                // OK now we need to load the field
                let fieldPtr = buildStructGEP bldr selfPtr (uint32 fieldIndex) "fieldPtr"
                let fieldValue = buildLoad bldr fieldPtr "fieldValue"
                goNext (fieldValue :: stackTail)

        | I_ldsflda _     //of ILFieldSpec
        | I_ldflda _      //of ILFieldSpec
        | I_stsfld _ -> noImpl () //of ILVolatility  *  ILFieldSpec
        | I_stfld (align, vol, field) -> //of ILAlignment * ILVolatility * ILFieldSpec
            match instStack with
            | value :: selfPtr :: stackTail ->
                // TODO alignment and volitility
                let selfJoint = typeHandles.[field.EnclosingTypeRef.Name]
                let cilFields = selfJoint.CILType.Fields.AsList
                let fieldIndex = List.findIndex (fun (f : ILFieldDef) -> f.Name = field.Name) cilFields

                // OK now we need to store the field
                let fieldPtr = buildStructGEP bldr selfPtr (uint32 fieldIndex) "fieldPtr"
                buildStore bldr value fieldPtr |> ignore
                goNext stackTail
            | _ -> failwith "instruction stack too low"

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
        | I_ldelema _ -> noImpl () //of ILReadonly * ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
        | I_ldelem_any (shape, ty) -> //of ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
            match shape with
            | ILArrayShape [(Some 0, None)] ->
                match instStack with
                | index :: arrObj :: stackTail ->
                    let arrPtr = buildStructGEP bldr arrObj 1u "arrPtr"
                    let arr = buildLoad bldr arrPtr "array"
                    let elemPtr = buildGEP bldr arr [|index|] "elemPtr"
                    let elem = buildLoad bldr elemPtr "elem"
                    
                    goNext (elem :: stackTail)
                | _ ->
                    failwith "instruction stack too low"
            | _ ->
                noImpl ()
        | I_stelem_any _  -> noImpl () //of ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
        | I_newarr (shape, ty) -> noImpl () //of ILArrayShape * ILType (* ILArrayShape = ILArrayShape.SingleDimensional for single dimensional arrays *)
        | I_ldlen ->
            match instStack with
            | arrObj :: stackTail ->
                let lenPtr = buildStructGEP bldr arrObj 0u "lenPtr"
                let len = buildLoad bldr lenPtr "len"
                
                goNext (len :: stackTail)
            | _ -> failwith "instruction stack too low"

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
*)

let genAlloca
        (bldr : BuilderRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (t : TypeReference)
        (name : string) =
    buildAlloca bldr (toLLVMType typeHandles t) (name + "Alloca")

let genLocal (bldr : BuilderRef) (typeHandles : Map<string, TypeHandleRef>) (l : VariableDefinition) =
    genAlloca bldr typeHandles l.VariableType (match l.Name with null -> "local" | n -> n)

let genParam (bldr : BuilderRef) (typeHandles : Map<string, TypeHandleRef>) (p : ParameterDefinition) =
    genAlloca bldr typeHandles p.ParameterType (match p.Name with null -> "param" | n -> n)

let genMethodBody
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (funMap : FunMap)
        (td : TypeDefinition)
        (md : MethodDefinition) =

    // create the entry block
    use bldr = new Builder(appendBasicBlock methodVal "entry")
    let args = Array.map (genParam bldr typeHandles) md.Body.AllParameters
    for i = 0 to args.Length - 1 do
        buildStore bldr (getParam methodVal (uint32 i)) args.[i] |> ignore
    let locals = Array.map (genLocal bldr typeHandles) (Array.ofSeq md.Body.Variables)
    let blocks = md.Body.BasicBlocks
    let blockDecs =
        [for b in blocks do
            let blockName = "block_" + string b.OffsetBytes
            yield (b.OffsetBytes, appendBasicBlock methodVal blockName)]
    match blockDecs with
    | [] -> failwith ("empty method body: " + md.Name)
    | (_, fstBlockDec) :: _ ->
        buildBr bldr fstBlockDec |> ignore
        //genCode moduleRef methodVal args locals typeHandles funMap (Map.ofList blockDecs) blocks
        let blockMap = Map.ofList blockDecs
        for i in 0 .. blocks.Length - 1 do
            use bldr = new Builder(blockMap.[blocks.[i].OffsetBytes])
            genInstructions
                bldr
                moduleRef
                methodVal
                args
                locals
                typeHandles
                funMap
                blockMap
                blocks.[i]
                []
                blocks.[i].Instructions
            
            // generate a fall-through jump to the next block
            // TODO: make sure this is OK even when current block ends with a terminating instruction
            if i < blocks.Length - 1 then
                buildBr bldr blockMap.[blocks.[i + 1].OffsetBytes] |> ignore

let genMethodDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (funMap : FunMap)
        (td : TypeDefinition)
        (md : MethodDefinition) =
    
    if md.HasBody then
        let fn = getNamedFunction moduleRef md.Name
        genMethodBody moduleRef fn typeHandles funMap td md
    else
        failwith "can only use genMethodDef for functions with a body"

let rec genTypeDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (funMap : FunMap)
        (td : TypeDefinition) =
    Seq.iter (genTypeDef moduleRef typeHandles funMap) td.NestedTypes
    Seq.iter (genMethodDef moduleRef typeHandles funMap td) td.Methods

let declareMethodDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (td : TypeDefinition)
        (md : MethodDefinition) =

    if md.HasBody then
        let paramTys = [|for p in md.Body.AllParameters -> toLLVMType typeHandles p.ParameterType|]
        let retTy = toLLVMType typeHandles md.ReturnType
        let funcTy = functionType retTy paramTys
        let fn = addFunction moduleRef md.Name funcTy
        
        let nameFun (i : int) (p : ParameterDefinition) =
            let llvmParam = getParam fn (uint32 i)
            match p.Name with
            | null -> setValueName llvmParam ("arg" + string i) |> ignore
            | name -> setValueName llvmParam name |> ignore
        Array.iteri nameFun md.Body.AllParameters
        
        (md.FullName, fn)
    else
        failwith "don't know how to declare method without a body"

let rec declareMethodDefs
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (td : TypeDefinition) =
    let nestedDecs = List.concat [for t in td.NestedTypes -> declareMethodDefs moduleRef typeHandles t]
    let methodDecs = [for m in td.Methods -> declareMethodDef moduleRef typeHandles td m]
    (td.Name, Map.ofList methodDecs) :: nestedDecs

let declareType (typeHandles : Map<string, TypeHandleRef>) (td : TypeDefinition) =
    let stFields = [|for f in td.Fields -> toLLVMType typeHandles f.FieldType|]
    let stTy = structType stFields false
    refineType typeHandles.[td.Name].ResolvedType stTy

let declareTypes (tds : TypeDefinition list) =
    // the reason that we build the type map before generating anything with
    // LLVM is that it allows us to remove the "forward declarations" of types
    // in the IL code. Since the real declarations all occur after the forward
    // declarations they will be the ones left behind in the map
    let rec flattenAndName (td : TypeDefinition) =
        (td.Name, td) :: List.collect flattenAndName (List.ofSeq td.NestedTypes)
    let tyMap = Map.ofList (List.collect flattenAndName tds)

    // generate the llvm ty handles that will hold all struct references
    // then perform the declarations
    let typeHandles = Map.map (fun _ td -> createTypeHandle (opaqueType ())) tyMap
    for _, td in Map.toList tyMap do
        declareType typeHandles td
    typeHandles

let genTypeDefs (llvmModuleRef : ModuleRef) (cilTypeDefs : seq<TypeDefinition>) =
    let cilTypeDefs = List.ofSeq cilTypeDefs
    let typeHandles = declareTypes cilTypeDefs
    for name, tyHandle in Map.toList typeHandles do
        addTypeName llvmModuleRef name tyHandle.ResolvedType |> ignore
    let funMap = Map.ofList <| List.concat [for t in cilTypeDefs -> declareMethodDefs llvmModuleRef typeHandles t]
    ()
    //Seq.iter (genTypeDef llvmModuleRef typeHandles funMap) cilTypeDefs

