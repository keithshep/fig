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

let objRefAsOption o =
    match o with
    | null -> None
    | _ -> Some o

type FunMap = Map<string , ValueRef>

type TypeHandleRef with
    member x.ResolvedType = resolveTypeHandle x

type ClassTypeRep (name : string, modRef : ModuleRef, staticRef : TypeHandleRef, instRef : TypeHandleRef) =
    let mutable staticVarsOpt = None : ValueRef option

    do
        addTypeName modRef (name + "Instance") instRef.ResolvedType |> ignore
        addTypeName modRef (name + "Static") staticRef.ResolvedType |> ignore
    
    member x.InstanceVarsTypeRef = instRef
    member x.InstanceVarsType = instRef.ResolvedType

    member x.StaticVarsTypeRef = staticRef
    member x.StaticVarsType = staticRef.ResolvedType

    member x.StaticVars =
        match staticVarsOpt with
        | Some staticVars -> staticVars
        | None ->
            let staticVars = addGlobal modRef x.StaticVarsType (name + "Global")
            staticVarsOpt <- Some staticVars
            staticVars

let rec saferTypeToLLVMType (typeHandles : Map<string, ClassTypeRep>) (ty : SaferTypeRef) =

    let noImpl () = failwithf "no impl for %A type yet" ty
    
    match ty with
    | Void -> voidType ()

    // TODO probably need a separate function for getting stack type vs normal type
    | Boolean -> int32Type ()
    | Char -> int32Type ()
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
    | String -> noImpl ()
    | Pointer ptrTy ->
        pointerType typeHandles.[ptrTy.ElementType.FullName].InstanceVarsType 0u
    | ByReference byRefType ->
        pointerType typeHandles.[byRefType.ElementType.FullName].InstanceVarsType 0u
    | ValueType typeRef ->
        // TODO have no idea if this is right
        typeHandles.[typeRef.FullName].InstanceVarsType
    | Class typeRef ->
        // TODO fix me
        pointerType typeHandles.[typeRef.FullName].InstanceVarsType 0u
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

and toLLVMType (typeHandles : Map<string, ClassTypeRep>) (ty : TypeReference) =
    saferTypeToLLVMType typeHandles (toSaferType ty)

type PrimSizeBytes = One = 1 | Two = 2 | Four = 4 | Eight = 8

// TODO this should be configurable
let nativeIntSize = PrimSizeBytes.Eight

let sizeOfStackType = function
    | Int32_ST | Float32_ST ->
        PrimSizeBytes.Four
    | Int64_ST | Float64_ST ->
        PrimSizeBytes.Eight
    | NativeInt_ST | ObjectRef_ST | ManagedPointer_ST ->
        // TODO not sure about objectref... and what about value types?
        nativeIntSize

let llvmIntTypeSized = function
    | PrimSizeBytes.One -> int8Type ()
    | PrimSizeBytes.Two -> int16Type ()
    | PrimSizeBytes.Four -> int32Type ()
    | PrimSizeBytes.Eight -> int64Type ()
    | s -> failwithf "invalid primitive size given: %i" (int s)

/// See: ECMA-335 Partition III 1.1, Partition I 12.1
///
/// From Partition III 1.1.1:
///
/// Loading integers on the stack causes
/// * zero-extending for types unsigned int8, unsigned int16, bool and char
/// * sign-extending for types int8 and int16
/// * zero-extends for unsigned indirect and element loads (ldind.u*, ldelem.u*, etc.)
/// * and sign-extends for signed indirect and element loads (ldind.i*, ldelem.i*, etc.
///
/// Storing to integers, booleans, and characters
/// (stloc, stfld, stind.i1, stelem.i2, etc.) truncates. Use the conv.ovf.* instructions
/// to detect when this truncation results in a value that doesn‘t correctly represent
/// the original value.
///
/// [Note: Short (i.e., 1- and 2-byte) integers are loaded as 4-byte numbers on all
/// architectures and these 4- byte numbers are always tracked as distinct from 8-byte
/// numbers. This helps portability of code by ensuring that the default arithmetic
/// behavior (i.e., when no conv or conv.ovf instruction is executed) will have identical
/// results on all implementations. end note]
///
/// Convert instructions that yield short integer values actually leave an int32 (32-bit)
/// value on the stack, but it is guaranteed that only the low bits have meaning
/// (i.e., the more significant bits are all zero for the unsigned conversions or a sign
/// extension for the signed conversions). To correctly simulate the full set of short
/// integer operations a conversion to a short integer is required before the div, rem,
/// shr, comparison and conditional branch instructions.
///
/// In addition to the explicit conversion instructions there are four cases where the CLI
/// handles short integers in a special way:
/// 1. Assignment to a local (stloc) or argument (starg) whose type is declared to be a
///    short integer type automatically truncates to the size specified for the local or argument.
/// 2. Loading from a local (ldloc) or argument (ldarg) whose type is declared to be a short
///    signed integer type automatically sign extends.
/// 3. Calling a procedure with an argument that is a short integer type is equivalent to
///    assignment to the argument value, so it truncates.
/// 4. Returning a value from a method whose return type is a short integer is modeled as
///    storing into a short integer within the called procedure (i.e., the CLI automatically
///    truncates) and then loading from a short integer within the calling procedure (i.e.,
///    the CLI automatically zero- or sign-extends).
///
/// In the last two cases it is up to the native calling convention to determine whether values
/// are actually truncated or extended, as well as whether this is done in the called procedure
/// or the calling procedure. The CIL instruction sequence is unaffected and it is as though
/// the CIL sequence included an appropriate conv instruction.
type StackItem (bldr:BuilderRef, value:ValueRef, ty:StackType) =
    member x.Value = value

    member x.AsStackType (asTy:StackType) =
        let cantConv () = failwithf "cannot convert %A to %A" ty asTy
        match asTy with
        | Int32_ST -> x.AsInt (false, PrimSizeBytes.Four)
        | Int64_ST -> x.AsInt (false, PrimSizeBytes.Eight)
        | NativeInt_ST -> x.AsNativeInt false
        | Float32_ST -> x.AsFloat32 ()
        | Float64_ST -> x.AsFloat64 ()
        | ObjectRef_ST ->
            match ty with
            | ObjectRef_ST -> value
            | _ -> cantConv ()
        | ManagedPointer_ST ->
            match ty with
            | ManagedPointer_ST -> value
            | _ -> cantConv ()

    member x.AsInt (asSigned:bool, asSize:PrimSizeBytes) =
        let size = sizeOfStackType ty
        match ty with
        | Int64_ST ->
            if asSize = size then
                value
            else
                failwith "implicit cast of Int64 values is not allowed"
        | Int32_ST ->
            if asSize = size then
                value
            elif asSize < size then
                // we need to truncate
                buildTrunc bldr value (llvmIntTypeSized asSize) "truncInt"
            else
                // TODO check which is correct
                // it's bigger which is not allowed
                failwith "implicit integer extension is not allowed"
        | _ ->
            failwithf "cannot convert %A to integer" ty

    member x.AsNativeInt (asSigned:bool) =
        match ty with
        | NativeInt_ST -> value
        | Int32_ST ->
            let size = sizeOfStackType ty
            if nativeIntSize = size then
                value
            elif nativeIntSize > size then
                // it's bigger so we need to either zero-extend or sign-extend
                let extFun = if asSigned then buildSExt else buildZExt
                extFun bldr value (llvmIntTypeSized nativeIntSize) "extendedInt"
            else
                failwith "internal error native int should never be less than Int32"
        | _ ->
            failwithf "implicit cast from %A to native int is not allowed" ty

    member x.AsFloat32 () =
        match ty with
        | Float32_ST -> value
        | Float64_ST -> buildFPTrunc bldr value (floatType()) "truncFloat"
        | _ -> failwithf "implicit cast from %A to float32 is not allowed" ty

    member x.AsFloat64 () =
        match ty with
        | Float32_ST -> buildFPExt bldr value (doubleType()) "extendedFloat"
        | Float64_ST -> value
        | _ -> failwithf "implicit cast from %A to float32 is not allowed" ty

    interface StackTyped with
        member x.StackType = ty

let rec genInstructions
        (bldr : BuilderRef)
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (args : ValueRef array)
        (locals : ValueRef array)
        (typeHandles : Map<string, ClassTypeRep>)
        (funMap : FunMap)
        (md : MethodDefinition)
        (blockMap : Map<int, BasicBlockRef>)
        (ilBB : BasicBlock)
        (stackVals : ValueRef list)
        (insts : AnnotatedInstruction list) =
    
    if not ilBB.InitStackTypes.IsEmpty then
        failwith "no impl yet for basic blocks with non-empty init stack states"

    match insts with
    | [] -> ()
    | inst :: instTail ->
        //printfn "Inst: %A" inst.Instruction
        
        let goNext (stackVals : ValueRef list) =
            genInstructions bldr moduleRef methodVal args locals typeHandles funMap md blockMap ilBB stackVals instTail
        let noImpl () = failwithf "instruction <<%A>> not implemented" inst.Instruction

        match inst.Instruction with
        // Basic
        | Add ->
            // The add instruction adds value2 to value1 and pushes the result
            // on the stack. Overflow is not detected for integral operations
            // (but see add.ovf); floating-point overflow returns +inf or -inf.
            match stackVals with
            | value2 :: value1 :: stackTail ->
                let addResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFAdd bldr value1 value2 "tmpFAdd"
                    | TypeKind.IntegerTypeKind ->
                        buildAdd bldr value1 value2 "tmpAdd"
                    | ty ->
                        failwithf "don't know how to add type: %A" ty
                goNext (addResult :: stackTail)
            | _ ->
                failwith "instruction stack too low"
        | AddOvf -> noImpl ()
        | AddOvfUn -> noImpl ()
        | And -> noImpl ()
        | Div ->
            match stackVals with
            | value2 :: value1 :: stackTail ->
                let divResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFDiv bldr value1 value2 "tmpFDiv"
                    | TypeKind.IntegerTypeKind ->
                        buildSDiv bldr value1 value2 "tmpDiv"
                    | ty ->
                        failwithf "don't know how to div type: %A" ty
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
            match stackVals with
            | [] -> failwith "instruction stack too low"
            | stackHead :: _ ->
                let headType = typeOf stackHead
                match getTypeKind headType with
                | TypeKind.IntegerTypeKind ->
                    if getIntTypeWidth headType = 32u then
                        goNext stackVals
                    else
                        failwith "not 32u"
                | _ ->
                    failwith "not an int kind"
        | ConvI8 -> noImpl ()
        | ConvR4 ->
            noImpl ()
        | ConvR8 ->
            match stackVals with
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
            match stackVals with
            | value2 :: value1 :: stackTail ->
                let mulResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFMul bldr value1 value2 "tmpFMul"
                    | TypeKind.IntegerTypeKind ->
                        buildMul bldr value1 value2 "tmpMul"
                    | ty ->
                        failwithf "don't know how to multiply type: %A" ty
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
            match stackVals with
            | value2 :: value1 :: stackTail ->
                let subResult =
                    match getTypeKind <| typeOf value1 with
                    | TypeKind.FloatTypeKind | TypeKind.DoubleTypeKind ->
                        buildFSub bldr value1 value2 "tmpFSub"
                    | TypeKind.IntegerTypeKind ->
                        buildSub bldr value1 value2 "tmpSub"
                    | ty ->
                        failwithf "don't know how to sub type: %A" ty
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
            // TODO this will probably only work in some limited cases
            match stackVals with
            | [] -> failwith "instruction stack too low"
            | stackHead :: _ -> goNext (stackHead :: stackVals)
        | Pop ->
            match stackVals with
            | [] -> failwith "instruction stack too low"
            | _ :: stackTail -> goNext stackTail
        | Ckfinite -> noImpl ()
        | Nop ->
            goNext stackVals
        | LdcI4 i ->
            let constResult = constInt (int32Type ()) (uint64 i) false // TODO correct me!!
            goNext (constResult :: stackVals)
        | LdcI8 i ->
            let constResult = constInt (int64Type ()) (uint64 i) false // TODO correct me!!
            goNext (constResult :: stackVals)
        | LdcR4 _ -> noImpl ()
        | LdcR8 r ->
            let constResult = constReal (doubleType ()) r
            goNext (constResult :: stackVals)
        | Ldarg paramDef ->
            let name = "tmp_" + paramDef.Name
            goNext (buildLoad bldr args.[paramDef.Sequence] name :: stackVals)
        | Ldarga paramDef ->
            let paramName = paramDef.Name
            let allParamNames = [|for p in md.AllParameters -> p.Name|]
            let paramIndex = Array.findIndex (fun name -> name = paramName) allParamNames
            goNext (args.[paramIndex] :: stackVals)
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
            goNext (loadResult :: stackVals)
        | Ldloca _ -> noImpl ()
        | Starg paramDef ->
            match stackVals with
            | [] -> failwith "instruction stack too low"
            | stackHead :: stackTail ->
                buildStore bldr stackHead args.[paramDef.Sequence] |> ignore
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
            match stackVals with
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
            match stackVals with
            | value2 :: value1 :: _ ->
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
                    failwithf "don't know how to compare type: %A" ty
            
            | _ ->
                failwith "instruction stack too low"

        | Switch (caseBlocks, defaultBlock) ->
            match stackVals with
            | [] -> failwith "empty instruction stack"
            | value :: _ ->
                let caseInts =
                    [|for i in 0 .. caseBlocks.Length - 1 ->
                        constInt (int32Type ()) (uint64 i) false|]
                let caseBlocks = [|for b in caseBlocks -> blockMap.[b.OffsetBytes]|]
                buildSwitchWithCases bldr value (Array.zip caseInts caseBlocks) blockMap.[defaultBlock.OffsetBytes]

        | Ret ->
            // TODO confirm void funs are [] and non-void are not
            match stackVals with
            | [] -> buildRetVoid bldr |> ignore
            | stackHead :: _ -> buildRet bldr stackHead |> ignore

        // Method call
        | Call (tailCall, methRef) ->
            // look up the corresponding LLVM function
            let methDef = methRef.Resolve ()
            let enclosingName = methDef.DeclaringType.FullName
            if enclosingName = "System.Object" && methDef.IsConstructor then
                //TODO stop ignoring object constructor calls
                goNext stackVals.Tail
            else
                let funRef = funMap.[methDef.FullName]

                let argCount = methDef.AllParameters.Length
                let args, stackTail = splitAt argCount stackVals
                let args = List.rev args
                let voidRet = methRef.ReturnType.MetadataType = MetadataType.Void
                let resultName = if voidRet then "" else "callResult"
                let callResult = buildCall bldr funRef (Array.ofList args) resultName
                if tailCall then setTailCall callResult true

                goNext (if voidRet then stackTail else callResult :: stackTail)

        | Callvirt _ -> noImpl ()
        | Calli _ -> noImpl ()
        | Ldftn _ -> noImpl ()
        | Newobj methRef ->
            // TODO implement GC along with object/class initialization code
            // FIXME naming is all screwed up! fix it
            let methDef = methRef.Resolve ()
            let enclosingName = methDef.DeclaringType.FullName
            if not methDef.IsConstructor then
                failwith "expected a .ctor here"
            else
                let funRef = funMap.[methDef.FullName]
                let llvmTy = typeHandles.[enclosingName].InstanceVarsType
                let newObj = buildMalloc bldr llvmTy ("new" + enclosingName)
                let args, stackTail = splitAt methRef.Parameters.Count stackVals
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
        | Ldsfld (_volatilePrefix, fieldRef) ->
            // TODO alignment and volitility
            let fieldName = fieldRef.FullName
            let declaringTy = fieldRef.DeclaringType.Resolve ()
            let staticCilFields = (fieldRef.DeclaringType.Resolve ()).StaticFields
            let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) staticCilFields

            // OK now we need to load the field
            let declClassRep = typeHandles.[declaringTy.FullName]
            let fieldPtr = buildStructGEP bldr declClassRep.StaticVars (uint32 fieldIndex) (fieldRef.Name + "Ptr")
            let fieldValue = buildLoad bldr fieldPtr (fieldRef.Name + "Value")
            goNext (fieldValue :: stackVals)

        | Ldfld (_unalignedPrefix, _volatilePrefix, fieldRef) ->
            match stackVals with
            | [] -> failwith "empty instruction stack"
            | selfPtr :: stackTail ->
                // TODO alignment and volitility
                let fieldName = fieldRef.FullName
                let cilFields = (fieldRef.DeclaringType.Resolve ()).InstanceFields
                let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) cilFields

                // OK now we need to load the field
                let fieldPtr = buildStructGEP bldr selfPtr (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                let fieldValue = buildLoad bldr fieldPtr (fieldRef.Name + "Value")
                goNext (fieldValue :: stackTail)

        | Ldsflda _ -> noImpl ()
        | Ldflda _ -> noImpl ()
        | Stsfld (_volatilePrefix, fieldRef) ->
            match stackVals with
            | [] -> failwith "empty instruction stack"
            | value :: stackTail ->
                // TODO volatility
                let fieldName = fieldRef.FullName
                let declaringTy = fieldRef.DeclaringType.Resolve ()
                let staticCilFields = declaringTy.StaticFields
                let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) staticCilFields

                // now store the field
                let declClassRep = typeHandles.[declaringTy.FullName]
                let fieldPtr = buildStructGEP bldr declClassRep.StaticVars (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                buildStore bldr value fieldPtr |> ignore
                goNext stackTail

        | Stfld (_unalignedPrefix, _volatilePrefix, fieldRef) ->
            match stackVals with
            | value :: selfPtr :: stackTail ->
                // TODO alignment and volitility
                let fieldName = fieldRef.FullName
                let cilFields = (fieldRef.DeclaringType.Resolve ()).InstanceFields
                let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) cilFields

                // OK now we need to store the field
                let fieldPtr = buildStructGEP bldr selfPtr (uint32 fieldIndex) (fieldRef.Name + "Ptr")
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
        | Ldelem _ ->
            match stackVals with
            | index :: arrObj :: stackTail ->
                let arrPtrAddr = buildStructGEP bldr arrObj 1u "arrPtrAddr"
                let arrPtr = buildLoad bldr arrPtrAddr "arrPtr"
                let elemAddr = buildGEP bldr arrPtr [|index|] "elemAddr"
                let elem = buildLoad bldr elemAddr "elem"

                goNext (elem :: stackTail)
            | _ ->
                failwith "instruction stack too low"
        | Stelem _ ->
            match stackVals with
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
            match stackVals with
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

                | _ -> failwithf "No impl yet for newing arrays of type %A" elemTypeRef
        | Ldlen ->
            match stackVals with
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
        (typeHandles : Map<string, ClassTypeRep>)
        (t : TypeReference)
        (name : string) =
    buildAlloca bldr (toLLVMType typeHandles t) (name + "Alloca")

let genLocal (bldr : BuilderRef) (typeHandles : Map<string, ClassTypeRep>) (l : VariableDefinition) =
    genAlloca bldr typeHandles l.VariableType (match l.Name with null -> "local" | n -> n)

let genParam (bldr : BuilderRef) (typeHandles : Map<string, ClassTypeRep>) (p : ParameterDefinition) =
    genAlloca bldr typeHandles p.ParameterType (match p.Name with null -> "param" | n -> n)

let genMethodBody
        (moduleRef : ModuleRef)
        (methodVal : ValueRef)
        (typeHandles : Map<string, ClassTypeRep>)
        (funMap : FunMap)
        (md : MethodDefinition) =

    //printfn "Method: %s" md.FullName

    // create the entry block
    use bldr = new Builder(appendBasicBlock methodVal "entry")
    let args = Array.map (genParam bldr typeHandles) md.AllParameters
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
        (typeHandles : Map<string, ClassTypeRep>)
        (funMap : FunMap)
        (md : MethodDefinition) =
    
    genMethodBody moduleRef funMap.[md.FullName] typeHandles funMap md

let rec genTypeDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, ClassTypeRep>)
        (funMap : FunMap)
        (td : TypeDefinition) =
    Seq.iter (genTypeDef moduleRef typeHandles funMap) td.NestedTypes
    for md in td.Methods do
        if md.HasBody then
            genMethodDef moduleRef typeHandles funMap md

let declareMethodDef
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, ClassTypeRep>)
        (md : MethodDefinition) =

    let fnName = if md.Name = "main" then "_main" else md.Name
    let nameFunParam (fn : ValueRef) (i : int) (p : ParameterDefinition) =
        let llvmParam = getParam fn (uint32 i)
        match p.Name with
        | null -> setValueName llvmParam ("arg" + string i)
        | name -> setValueName llvmParam name

    if md.HasBody then
        let paramTys = [|for p in md.AllParameters -> toLLVMType typeHandles p.ParameterType|]
        let retTy = toLLVMType typeHandles md.ReturnType
        let funcTy = functionType retTy paramTys
        let fn = addFunction moduleRef fnName funcTy
        
        Array.iteri (nameFunParam fn) md.AllParameters
        
        (md.FullName, fn)
    elif md.HasPInvokeInfo then
        let pInv = md.PInvokeInfo

        // TODO for now assuming that we don't need to use "dlopen"
        if pInv.Module.Name <> "libc.dll" then
            failwith "sorry! only works with libc for now. No dlopen etc."

        if pInv.EntryPoint <> md.Name then
            failwithf
                "sorry! for now the entry point name (%s) and function name (%s) must be the same"
                pInv.EntryPoint
                md.Name

        let paramTys = [|for p in md.Parameters -> toLLVMType typeHandles p.ParameterType|]
        let retTy = toLLVMType typeHandles md.ReturnType
        let funcTy = functionType retTy paramTys
        let fn = addFunction moduleRef fnName funcTy
        setLinkage fn Linkage.ExternalLinkage

        Seq.iteri (nameFunParam fn) md.Parameters

        (md.FullName, fn)
    else
        failwith "don't know how to declare method without a body"

let rec declareMethodDefs
        (moduleRef : ModuleRef)
        (typeHandles : Map<string, ClassTypeRep>)
        (td : TypeDefinition) =
    seq {
        for m in td.Methods do
            yield declareMethodDef moduleRef typeHandles m
        for t in td.NestedTypes do
            yield! declareMethodDefs moduleRef typeHandles t
    }

let declareType (typeHandles : Map<string, ClassTypeRep>) (td : TypeDefinition) =
    let instanceFields =
        [|for f in td.InstanceFields do
            yield toLLVMType typeHandles f.FieldType|]
    let instanceTy = structType instanceFields false
    refineType typeHandles.[td.FullName].InstanceVarsType instanceTy

    let staticFields =
        [|for f in td.StaticFields do
            yield toLLVMType typeHandles f.FieldType|]
    let staticTy = structType staticFields false
    refineType typeHandles.[td.FullName].StaticVarsType staticTy

let declareTypes (llvmModuleRef : ModuleRef) (tds : TypeDefinition list) =
    // the reason that we build the type map before generating anything with
    // LLVM is that it allows us to remove the "forward declarations" of types
    // in the IL code. Since the real declarations all occur after the forward
    // declarations they will be the ones left behind in the map
    let rec flattenAndName (td : TypeDefinition) =
        (td.FullName, td) :: List.collect flattenAndName (List.ofSeq td.NestedTypes)
    let tyMap = Map.ofList (List.collect flattenAndName tds)

    // generate the llvm ty handles that will hold all struct references
    // then perform the declarations
    let makeOpaque () = createTypeHandle (opaqueType ())
    let makeClassTyRep name _ = new ClassTypeRep(name, llvmModuleRef, makeOpaque (), makeOpaque ())
    let typeHandles = Map.map makeClassTyRep tyMap
    for _, td in Map.toList tyMap do
        declareType typeHandles td
    typeHandles

let genMainFunction
        (funMap : FunMap)
        (methDef : MethodDefinition)
        (llvmModuleRef : ModuleRef) =

    let argcTy = int32Type ()
    let argvTy = pointerType (pointerType (int8Type ()) 0u) 0u
    let cMainFnTy = functionType (int32Type ()) [|argcTy; argvTy|]
    let cMainFn = addFunction llvmModuleRef "main" cMainFnTy
    setValueName (getParam cMainFn 0u) "argc"
    setValueName (getParam cMainFn 0u) "argv"

    use bldr = new Builder(appendBasicBlock cMainFn "entry")
    let callResult =
        let voidRet = methDef.ReturnType.MetadataType = MetadataType.Void
        let resultName = if voidRet then "" else "result"
        match methDef.AllParameters with
        | [||] -> buildCall bldr funMap.[methDef.FullName] [||] resultName
        | [|cmdLineArgs|] ->
            let safeParamTy = toSaferType cmdLineArgs.ParameterType
            let badType () =
                failwithf "main function should take no arguments or String[] but instead found %A" cmdLineArgs
            match safeParamTy with
            | Array elemTy ->
                match toSaferType elemTy with
                | String ->
                    // TODO build args string array
                    //buildCall bldr funMap.[cilMainMeth.FullName] [||] "result"
                    failwith "main taking string array not yet implemented"
                | _ -> badType ()
            | _ -> badType ()
        | ps -> failwithf "expected main method to have zero or one argument but found %i arguments" ps.Length

    match toSaferType methDef.ReturnType with
    | Void  -> buildRet bldr (constInt (int32Type ()) 0uL false) |> ignore
    | Int32 -> buildRet bldr callResult |> ignore
    | retTy -> failwith "don't know how to deal with main return type of %A" retTy

let genTypeDefs
        (methDefOpt : MethodDefinition option)
        (llvmModuleRef : ModuleRef)
        (cilTypeDefs : seq<TypeDefinition>) =

    let cilTypeDefs = List.ofSeq cilTypeDefs
    let typeHandles = declareTypes llvmModuleRef cilTypeDefs
    let funMap =
        seq {for t in cilTypeDefs do yield! declareMethodDefs llvmModuleRef typeHandles t}
        |> Map.ofSeq
    Seq.iter (genTypeDef llvmModuleRef typeHandles funMap) cilTypeDefs
    match methDefOpt with
    | None -> ()
    | Some methDef -> genMainFunction funMap methDef llvmModuleRef
