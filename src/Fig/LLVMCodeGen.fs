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

type FunMap = Map<string , ValueRef>

type TypeHandleRef with
    member x.ResolvedType with get () = resolveTypeHandle x

let rec saferTypeToLLVMType (typeHandles : Map<string, TypeHandleRef>) (ty : SaferTypeRef) =

    let noImpl () = failwithf "no impl for %A type yet" ty
    
    match ty with
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
    | Pointer _
    | ByReference _
    | ValueType _ ->
        noImpl ()
    | Class typeRef ->
        // TODO fix me
        pointerType typeHandles.[typeRef.FullName].ResolvedType 0u
    | Var _ ->
        noImpl ()
    | Array arrTy ->
        if arrTy.Rank = 1 then
            let dim0 = arrTy.Dimensions.[0]
            match nullableAsOption dim0.LowerBound, nullableAsOption dim0.UpperBound with
            | ((None | Some 0), None) -> //(0, null) ->
                // LLVM docs say:
                // "... 'variable sized array' addressing can be implemented in LLVM
                // with a zero length array type". So, we implement this as a struct
                // which contains a length element and an array element
                let elemTy = toLLVMType typeHandles arrTy.ElementType
                let basicArrTy = pointerType elemTy 0u
                // FIXME array len should correspond to "native unsigned int" not int32
                pointerType (structType [|int32Type (); basicArrTy|] false) 0u
            | lowerBound, upperBound ->
                failwithf "dont know how to deal with given array shape yet %A->%A" lowerBound upperBound
        else
            failwithf "arrays of rank %i not yet implemented" arrTy.Rank
    | GenericInstance _
    | TypedByReference
    | IntPtr
    | UIntPtr
    | FunctionPointer _
    | Object
    | MVar _
    | RequiredModifier _
    | OptionalModifier _
    | Sentinel _
    | Pinned _ ->
        noImpl ()

and toLLVMType (typeHandles : Map<string, TypeHandleRef>) (ty : TypeReference) =
    saferTypeToLLVMType typeHandles (toSaferType ty)

let rec genInstructions
        (bldr : BuilderRef)
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : ValueRef array)
        (locals : ValueRef array)
        (typeHandles : Map<string, TypeHandleRef>)
        (funMap : FunMap)
        (md : MethodDefinition)
        (blockMap : Map<int, BasicBlockRef>)
        (ilBB : BasicBlock)
        (instStack : ValueRef list)
        (insts : AnnotatedInstruction list) =

    match insts with
    | [] -> ()
    | inst :: instTail ->
        let goNext (instStack : ValueRef list) =
            genInstructions bldr moduleRef methodVal args locals typeHandles funMap md blockMap ilBB instStack instTail
        let noImpl () = failwith (sprintf "instruction <<%A>> not implemented" inst.Instruction)

        match inst.Instruction with
        // Basic
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
        | AddOvf -> noImpl ()
        | AddOvfUn -> noImpl ()
        | And -> noImpl ()
        | Div ->
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
        | DivUn -> noImpl ()
        | Ceq -> noImpl ()
        | Cgt -> noImpl ()
        | CgtUn -> noImpl ()
        | Clt -> noImpl ()
        | CltUn -> noImpl ()
        | ConvI1 -> noImpl ()
        | ConvI2 ->
            noImpl ()
        | ConvI4 ->
            match instStack with
            | [] -> failwith "instruction stack too low"
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
        | ConvI8 -> noImpl ()
        | ConvR4 ->
            noImpl ()
        | ConvR8 ->
            match instStack with
            | [] -> failwith "instruction stack too low"
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
        | ConvU4 -> noImpl ()
        | ConvU8 -> noImpl ()
        | ConvU2 -> noImpl ()
        | ConvU1 -> noImpl ()
        | ConvI -> noImpl ()
        | ConvU -> noImpl ()

        | ConvRUn -> noImpl ()

        | ConvOvfI1Un -> noImpl ()
        | ConvOvfI2Un -> noImpl ()
        | ConvOvfI4Un -> noImpl ()
        | ConvOvfI8Un -> noImpl ()
        | ConvOvfU1Un -> noImpl ()
        | ConvOvfU2Un -> noImpl ()
        | ConvOvfU4Un -> noImpl ()
        | ConvOvfU8Un -> noImpl ()
        | ConvOvfIUn -> noImpl ()
        | ConvOvfUUn -> noImpl ()

        | ConvOvfI1 -> noImpl ()
        | ConvOvfU1 -> noImpl ()
        | ConvOvfI2 -> noImpl ()
        | ConvOvfU2 -> noImpl ()
        | ConvOvfI4 -> noImpl ()
        | ConvOvfU4 -> noImpl ()
        | ConvOvfI8 -> noImpl ()
        | ConvOvfU8 -> noImpl ()
        | ConvOvfI -> noImpl ()
        | ConvOvfU -> noImpl ()
        | Mul ->
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
        | MulOvf -> noImpl ()
        | MulOvfUn -> noImpl ()
        | Rem -> noImpl ()
        | RemUn -> noImpl ()
        | Shl -> noImpl ()
        | Shr -> noImpl ()
        | ShrUn -> noImpl ()
        | Sub ->
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
        | SubOvf -> noImpl ()
        | SubOvfUn -> noImpl ()
        | Xor -> noImpl ()
        | Or -> noImpl ()
        | Neg -> noImpl ()
        | Not -> noImpl ()
        | Ldnull -> noImpl ()
        | Dup ->
            match instStack with
            | [] -> failwith "instruction stack too low"
            | stackHead :: _ ->
                // TODO this will probably only work in some limited cases
                goNext (stackHead :: instStack)
        | Pop -> noImpl ()
        | Ckfinite -> noImpl ()
        | Nop ->
            goNext instStack
        | LdcI4 i ->
            let constResult = constInt (int32Type ()) (uint64 i) false // TODO correct me!!
            goNext (constResult :: instStack)
        | LdcI8 i ->
            let constResult = constInt (int64Type ()) (uint64 i) false // TODO correct me!!
            goNext (constResult :: instStack)
        | LdcR4 r -> noImpl ()
        | LdcR8 r ->
            let constResult = constReal (doubleType ()) r
            goNext (constResult :: instStack)
        | Ldarg paramDef ->
            // TODO after http://groups.google.com/group/mono-cecil/browse_thread/thread/ce63993cd8cb3c98
            // is fixed we can just use paramDef.Sequence
            let paramName = paramDef.Name
            let allParamNames = [|for p in md.Body.AllParameters -> p.Name|]
            let paramIndex = Array.findIndex (fun name -> name = paramName) allParamNames
            let name = "tmp_" + paramDef.Name
            goNext (buildLoad bldr args.[paramIndex] name :: instStack)
        | Ldarga _ -> noImpl ()
        | LdindI1 _ -> noImpl ()
        | LdindU1 _ -> noImpl ()
        | LdindI2 _ -> noImpl ()
        | LdindU2 _ -> noImpl ()
        | LdindI4 _ -> noImpl ()
        | LdindU4 _ -> noImpl ()
        | LdindI8 _ -> noImpl ()
        | LdindI _ -> noImpl ()
        | LdindR4 _ -> noImpl ()
        | LdindR8 _ -> noImpl ()
        | LdindRef _ -> noImpl ()
        | Ldloc varDef ->
            let loadResult = buildLoad bldr locals.[varDef.Index] "tmp"
            goNext (loadResult :: instStack)
        | Ldloca _ -> noImpl ()
        | Starg paramDef ->
            match instStack with
            | [] -> failwith "instruction stack too low"
            | stackHead :: stackTail ->
                // TODO after http://groups.google.com/group/mono-cecil/browse_thread/thread/ce63993cd8cb3c98
                // is fixed we can just use paramDef.Sequence
                let paramName = paramDef.Name
                let allParamNames = [|for p in md.Body.AllParameters -> p.Name|]
                let paramIndex = Array.findIndex (fun name -> name = paramName) allParamNames
                buildStore bldr stackHead args.[paramIndex] |> ignore
                goNext stackTail
        | StindRef _ -> noImpl ()
        | StindI1 _ -> noImpl ()
        | StindI2 _ -> noImpl ()
        | StindI4 _ -> noImpl ()
        | StindI8 _ -> noImpl ()
        | StindR4 _ -> noImpl ()
        | StindR8 _ -> noImpl ()
        | StindI _ -> noImpl ()
        | Stloc varDef ->
            match instStack with
            | [] -> failwith "instruction stack too low"
            | stackHead :: stackTail ->
                buildStore bldr stackHead locals.[varDef.Index] |> ignore
                goNext stackTail

        // Control transfer
        | Br bb ->
            buildBr bldr blockMap.[bb.OffsetBytes] |> ignore
        | Jmp _ ->
            noImpl ()
        | Beq (ifBB, elseBB) | Bge (ifBB, elseBB) | Bgt (ifBB, elseBB)
        | Ble (ifBB, elseBB) | Blt (ifBB, elseBB) | BneUn (ifBB, elseBB)
        | BgeUn (ifBB, elseBB) | BgtUn (ifBB, elseBB) | BleUn (ifBB, elseBB)
        | BltUn (ifBB, elseBB) | Brfalse (ifBB, elseBB) | Brtrue (ifBB, elseBB) ->
            match instStack with
            | value2 :: value1 :: stackTail ->
                let isIntCmp = true
                match getTypeKind <| typeOf value1 with
                | TypeKind.IntegerTypeKind ->
                    let brWith op =
                        let brTest = buildICmp bldr op value1 value2 "brTest"
                        buildCondBr bldr brTest blockMap.[ifBB.OffsetBytes] blockMap.[elseBB.OffsetBytes] |> ignore
                    
                    match inst.Instruction with
                    | Beq _     -> brWith IntPredicate.IntEQ
                    | Bge _     -> brWith IntPredicate.IntSGE
                    | BgeUn _   -> brWith IntPredicate.IntUGE
                    | Bgt _     -> brWith IntPredicate.IntSGT
                    | BgtUn _   -> brWith IntPredicate.IntUGT
                    | Ble _     -> brWith IntPredicate.IntSLE
                    | BleUn _   -> brWith IntPredicate.IntULE
                    | Blt _     -> brWith IntPredicate.IntSLT
                    | BltUn _   -> brWith IntPredicate.IntULT
                    | BneUn _   -> brWith IntPredicate.IntNE
                    | Brfalse _ -> noImpl ()
                    | Brtrue _  -> noImpl ()
                    | _         -> failwith "whoa! this error should be impossible!"
                | ty ->
                    failwith (sprintf "don't know how to compare type: %A" ty)
            
            | _ ->
                failwith "instruction stack too low"

        | Switch (caseBlocks, defaultBlock) ->
            match instStack with
            | [] -> failwith "empty instruction stack"
            | value :: stackTail ->
                let caseInts =
                    [|for i in 0 .. caseBlocks.Length - 1 ->
                        constInt (int32Type ()) (uint64 i) false|]
                let caseBlocks = [|for b in caseBlocks -> blockMap.[b.OffsetBytes]|]
                buildSwitchWithCases bldr value (Array.zip caseInts caseBlocks) blockMap.[defaultBlock.OffsetBytes]

        | Ret ->
            // TODO confirm void funs are [] and non-void are not
            match instStack with
            | [] -> buildRetVoid bldr |> ignore
            | stackHead :: stackTail -> buildRet bldr stackHead |> ignore

        // Method call
        | Call (tailCall, methRef) ->
            // look up the corresponding LLVM function
            let methDef = methRef.Resolve ()
            let enclosingName = methDef.DeclaringType.FullName
            if enclosingName = "System.Object" && methDef.IsConstructor then
                //TODO stop ignoring object constructor calls
                goNext instStack.Tail
            else
                let funRef = funMap.[methDef.FullName]

                let mb = methDef.Body
                let argCount = mb.AllParameters.Length
                let args, stackTail = splitAt argCount instStack
                let args = List.rev args
                let callResult = buildCall bldr funRef (Array.ofList args) "callResult"
                if tailCall then setTailCall callResult true

                match methRef.ReturnType.MetadataType with
                | MetadataType.Void -> goNext stackTail
                | _ -> goNext (callResult :: stackTail)

        | Callvirt _ -> noImpl ()
        | Calli _ -> noImpl ()
        | Ldftn _ -> noImpl ()
        | Newobj methRef ->
            // TODO implement GC
            // FIXME naming is all screwed up! fix it
            let methDef = methRef.Resolve ()
            let enclosingName = methDef.DeclaringType.FullName
            if not methDef.IsConstructor then
                failwith "expected a .ctor here"
            else
                let funRef = funMap.[methDef.FullName]
                let llvmTy = typeHandles.[enclosingName].ResolvedType
                let newObj = buildMalloc bldr llvmTy ("new" + enclosingName)
                let args, stackTail = splitAt methRef.Parameters.Count instStack
                let args = newObj :: List.rev args
                buildCall bldr funRef (Array.ofList args) "" |> ignore
                goNext (newObj :: stackTail)

        // Exceptions
        | Throw -> noImpl ()
        | Endfinally -> noImpl ()
        | Endfilter -> noImpl ()
        | Leave _ -> noImpl ()
        | Rethrow -> noImpl ()

        // Object instructions
        | Ldsfld _ -> noImpl ()
        | Ldfld (unalignedPrefix, volatilePrefix, fieldRef) ->
            match instStack with
            | [] -> failwith "empty instruction stack"
            | selfPtr :: stackTail ->
                // TODO alignment and volitility
                let fieldName = fieldRef.FullName
                let cilFields = (fieldRef.DeclaringType.Resolve ()).Fields
                let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) cilFields

                // OK now we need to load the field
                let fieldPtr = buildStructGEP bldr selfPtr (uint32 fieldIndex) "fieldPtr"
                let fieldValue = buildLoad bldr fieldPtr "fieldValue"
                goNext (fieldValue :: stackTail)

        | Ldsflda _ -> noImpl ()
        | Ldflda _ -> noImpl ()
        | Stsfld _ -> noImpl ()
        | Stfld (unalignedPrefix, volatilePrefix, fieldRef) ->
            match instStack with
            | value :: selfPtr :: stackTail ->
                // TODO alignment and volitility
                let fieldName = fieldRef.FullName
                let cilFields = (fieldRef.DeclaringType.Resolve ()).Fields
                let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) cilFields

                // OK now we need to store the field
                let fieldPtr = buildStructGEP bldr selfPtr (uint32 fieldIndex) "fieldPtr"
                buildStore bldr value fieldPtr |> ignore
                goNext stackTail
            | _ -> failwith "instruction stack too low"

        | Ldstr _ -> noImpl ()
        | Isinst _ -> noImpl ()
        | Castclass _ -> noImpl ()
        | Ldtoken _ -> noImpl ()
        | Ldvirtftn _ -> noImpl ()

        // Value type instructions
        | Cpobj _ -> noImpl ()
        | Initobj _ -> noImpl ()
        | Ldobj _ -> noImpl ()
        | Stobj _ -> noImpl ()
        | Box _ -> noImpl ()
        | Unbox _ -> noImpl ()
        | UnboxAny _ -> noImpl ()
        | Sizeof _ -> noImpl ()

        // Generalized array instructions. In AbsIL these instructions include
        // both the single-dimensional variants (with ILArrayShape == ILArrayShape.SingleDimensional)
        // and calls to the "special" multi-dimensional "methods" such as
        //   newobj void string[,]::.ctor(int32, int32)
        //   call string string[,]::Get(int32, int32)
        //   call string& string[,]::Address(int32, int32)
        //   call void string[,]::Set(int32, int32,string)
        | Ldelem typeRef ->
            match instStack with
            | index :: arrObj :: stackTail ->
                //let arrPtr = buildStructGEP bldr arrObj 1u "arrPtr"
                let arrPtrAddr = buildStructGEP bldr arrObj 1u "arrPtrAddr"
                let arrPtr = buildLoad bldr arrPtrAddr "arrPtr"
                let elemAddr = buildGEP bldr arrPtr [|index|] "elemAddr"
                let elem = buildLoad bldr elemAddr "elem"

                goNext (elem :: stackTail)
            | _ ->
                failwith "instruction stack too low"
        | Stelem _ ->
            match instStack with
            | value :: index :: arrObj :: stackTail ->
                //let arrPtr = buildStructGEP bldr arrObj 1u "arrPtr"
                let arrPtrAddr = buildStructGEP bldr arrObj 1u "arrPtrAddr"
                let arrPtr = buildLoad bldr arrPtrAddr "arrPtr"
                let elemAddr = buildGEP bldr arrPtr [|index|] "elemAddr"
                buildStore bldr value elemAddr |> ignore

                goNext stackTail
            | _ ->
                failwith "instruction stack too low"
        | Ldelema _ -> noImpl ()
        | LdelemI1 -> noImpl ()
        | LdelemU1 -> noImpl ()
        | LdelemI2 -> noImpl ()
        | LdelemU2 -> noImpl ()
        | LdelemI4 -> noImpl ()
        | LdelemU4 -> noImpl ()
        | LdelemI8 -> noImpl ()
        | LdelemI -> noImpl ()
        | LdelemR4 -> noImpl ()
        | LdelemR8 -> noImpl ()
        | LdelemRef -> noImpl ()
        | StelemI -> noImpl ()
        | StelemI1 -> noImpl ()
        | StelemI2 -> noImpl ()
        | StelemI4 -> noImpl ()
        | StelemI8 -> noImpl ()
        | StelemR4 -> noImpl ()
        | StelemR8 -> noImpl ()
        | StelemRef -> noImpl ()
        | Newarr elemTypeRef ->
            match instStack with
            | [] -> failwith "instruction stack too low"
            | numElems :: stackTail ->
                match toSaferType elemTypeRef with
                | Double ->
                    // allocate the array to the heap
                    // TODO it seems pretty lame to have this code here. need to think
                    // about how this should really be structured
                    let elemTy = toLLVMType typeHandles elemTypeRef
                    let newArr = buildArrayMalloc bldr elemTy numElems "newArr"

                    let basicArrTy = pointerType elemTy 0u
                    // FIXME array len should correspond to "native unsigned int" not int32
                    let arrObjTy = structType [|int32Type (); basicArrTy|] false
                    let newArrObj = buildMalloc bldr arrObjTy ("newArrObj")
                    
                    // fill in the array object
                    let lenAddr = buildStructGEP bldr newArrObj 0u "lenAddr"
                    buildStore bldr numElems lenAddr |> ignore
                    let arrPtrAddr = buildStructGEP bldr newArrObj 1u "arrPtrAddr"
                    buildStore bldr newArr arrPtrAddr |> ignore

                    goNext (newArrObj :: stackTail)

                | _ -> failwith "No impl yet for newing arrays of type %A" elemTypeRef
        | Ldlen ->
            match instStack with
            | [] -> failwith "instruction stack too low"
            | arrObj :: stackTail ->
                let lenAddr = buildStructGEP bldr arrObj 0u "lenAddr"
                let len = buildLoad bldr lenAddr "len"
                
                goNext (len :: stackTail)

        // "System.TypedReference" related instructions: almost
        // no languages produce these, though they do occur in mscorlib.dll
        // System.TypedReference represents a pair of a type and a byref-pointer
        // to a value of that type. 
        | Mkrefany _ -> noImpl ()
        | Refanytype -> noImpl ()
        | Refanyval _ -> noImpl ()
        
        // Debug-specific 
        | Break -> noImpl ()

        // Varargs - C++ only
        | Arglist -> noImpl ()

        // Local aggregates, i.e. stack allocated data (alloca) : C++ only
        | Localloc -> noImpl ()
        | Cpblk _ -> noImpl ()
        | Initblk _ -> noImpl ()

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
    | [] -> failwith ("empty method body: " + md.FullName)
    | (_, fstBlockDec) :: _ ->
        buildBr bldr fstBlockDec |> ignore
        let blockMap = Map.ofList blockDecs
        for i in 0 .. blocks.Length - 1 do
            if not blocks.[i].InitStackTypes.IsEmpty then
                failwith "don't yet know how to deal with non empty basic blocks!!"
            use bldr = new Builder(blockMap.[blocks.[i].OffsetBytes])
            genInstructions
                bldr
                moduleRef
                methodVal
                args
                locals
                typeHandles
                funMap
                md
                blockMap
                blocks.[i]
                []
                blocks.[i].Instructions

let genMethodDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (funMap : FunMap)
        (md : MethodDefinition) =
    
    if md.HasBody then
        genMethodBody moduleRef funMap.[md.FullName] typeHandles funMap md
    else
        failwith "can only use genMethodDef for functions with a body"

let rec genTypeDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (funMap : FunMap)
        (td : TypeDefinition) =
    Seq.iter (genTypeDef moduleRef typeHandles funMap) td.NestedTypes
    Seq.iter (genMethodDef moduleRef typeHandles funMap) td.Methods

let declareMethodDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, TypeHandleRef>)
        (td : TypeDefinition)
        (md : MethodDefinition) =
    if md.HasBody then
        let paramTys = [|for p in md.Body.AllParameters -> toLLVMType typeHandles p.ParameterType|]
        let retTy = toLLVMType typeHandles md.ReturnType
        let funcTy = functionType retTy paramTys
        let fn = addFunction moduleRef md.Name funcTy // TODO are name collisions allowed here?
        
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
    seq {
        for m in td.Methods do
            yield declareMethodDef moduleRef typeHandles td m
        for t in td.NestedTypes do
            yield! declareMethodDefs moduleRef typeHandles t
    }

let declareType (typeHandles : Map<string, TypeHandleRef>) (td : TypeDefinition) =
    let stFields = [|for f in td.Fields -> toLLVMType typeHandles f.FieldType|]
    let stTy = structType stFields false
    refineType typeHandles.[td.FullName].ResolvedType stTy

let declareTypes (tds : TypeDefinition list) =
    // the reason that we build the type map before generating anything with
    // LLVM is that it allows us to remove the "forward declarations" of types
    // in the IL code. Since the real declarations all occur after the forward
    // declarations they will be the ones left behind in the map
    let rec flattenAndName (td : TypeDefinition) =
        (td.FullName, td) :: List.collect flattenAndName (List.ofSeq td.NestedTypes)
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
    let funMap =
        seq {for t in cilTypeDefs do yield! declareMethodDefs llvmModuleRef typeHandles t}
        |> Map.ofSeq
    Seq.iter (genTypeDef llvmModuleRef typeHandles funMap) cilTypeDefs
