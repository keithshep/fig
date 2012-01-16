module Fig.LLVMCodeGen

open Fig.CecilExt

open Mono.Cecil
open Mono.Cecil.Cil

open LLVM.Generated.Core
open LLVM.Core
open LLVM.Extra

open System.Collections.Generic

let nameOrDefault (name : string) (def : string) : string =
    match name with
    | null | "" -> def
    | _ -> name

let nullableAsOption (n : System.Nullable<'a>) =
    if n.HasValue then
        Some n.Value
    else
        None

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

type [<AbstractClass>] DefAndImpl<'T> () =
    let mutable valueOpt = None : 'T option

    abstract member Define : unit -> 'T
    abstract member Implement : 'T -> unit

    member x.Value =
        match valueOpt with
        | Some value -> value
        | None ->
            let value = x.Define()
            valueOpt <- Some value
            x.Implement value
            value

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
type StackItem (bldr:BuilderRef, value:ValueRef, ty:StackType, tyRefOpt:TypeReference option) =
    
    static member StackItemFromAny (bldr:BuilderRef, value:ValueRef, tyRef:TypeReference) =
        let ty = toSaferType tyRef

        let noImpl () = failwithf "cannot convert %A into a stack item" ty

        match ty with
        | Void -> noImpl ()
        | Boolean | Char | Byte | UInt16 ->
            let value = buildZExt bldr value (int32Type()) "extendedInt"
            new StackItem(bldr, value, StackType.Int32_ST, Some tyRef)
        | SByte | Int16 ->
            let value = buildSExt bldr value (int32Type()) "extendedInt"
            new StackItem(bldr, value, StackType.Int32_ST, Some tyRef)
        | Int32 | UInt32 -> new StackItem(bldr, value, StackType.Int32_ST, Some tyRef)
        | Int64 | UInt64 -> new StackItem(bldr, value, StackType.Int64_ST, Some tyRef)
        | Single -> noImpl ()
        | Double -> new StackItem(bldr, value, StackType.Float32_ST, Some tyRef)
        | String -> noImpl ()
        | Pointer _ptrTy -> new StackItem(bldr, value, StackType.ManagedPointer_ST, Some tyRef)
        | ByReference _byRefType ->
            // TODO not sure this is always right
            new StackItem(bldr, value, StackType.ManagedPointer_ST, Some tyRef)
        | ValueType _typeRef ->
            noImpl ()
            // TODO have no idea if this is right
            //assemGen.[typeRef.FullName].InstanceVarsType
        | Class _typeRef -> new StackItem(bldr, value, StackType.ObjectRef_ST, Some tyRef)
        | Var _ ->
            noImpl ()
        | Array _arrTy -> new StackItem(bldr, value, StackType.ObjectRef_ST, Some tyRef)
        | GenericInstance _
        | TypedByReference
        | IntPtr | UIntPtr -> new StackItem(bldr, value, StackType.NativeInt_ST, Some tyRef)
        | FunctionPointer _
        | Object
        | MVar _
        | RequiredModifier _
        | OptionalModifier _
        | Sentinel _
        | Pinned _ ->
            noImpl ()

    static member StackItemFromInt (bldr:BuilderRef, value:ValueRef, signed:bool, size:PrimSizeBytes) =
        match size with
        | PrimSizeBytes.Eight -> new StackItem(bldr, value, Int64_ST, None)
        | PrimSizeBytes.Four -> new StackItem(bldr, value, Int32_ST, None)
        | PrimSizeBytes.Two | PrimSizeBytes.One ->
            let extFun = if signed then buildSExt else buildZExt
            let value = extFun bldr value (int32Type()) "extendedInt"
            new StackItem(bldr, value, Int32_ST, None)
        | _ -> failwith "does not compute"
    
    member x.Value = value

    member x.AsPointerTo (assemGen:AssemGen, tyRef:TypeReference) : ValueRef =
        //let tyRef = tyRef.Resolve()
        let ty = toSaferType tyRef

        let noImpl () = failwithf "no implementation for creating a pointer to %A" ty
        (*if not tyRef.IsPrimitive then
            // TODO how should we implement for non primitives
            noImpl ()*)
        let ptrTy = pointerType (TypeUtil.LLVMVarTypeOf assemGen tyRef) 0u

        // TODO is this really the way to do this? maybe the types should be normalized on construction
        match getTypeKind (typeOf x.Value) with
        | TypeKind.IntegerTypeKind ->
            buildIntToPtr bldr x.Value ptrTy "ptrFromInt"
        | TypeKind.PointerTypeKind ->
            buildBitCast bldr x.Value ptrTy "ptr"
        | tk ->
            failwithf "cannot convert type kind %A to pointer" tk

    member x.AsInvokable(assemGen:AssemGen, tyRef:TypeReference) : ValueRef =
        //let tyRef = tyRef.Resolve()
        let ty = toSaferType tyRef

        let noImpl () = failwith "no implementation for creating an invokable from %A" ty
        if not tyRef.IsPrimitive then
            // TODO how should we implement for non primitives
            noImpl ()
        let ptrTy = pointerType (TypeUtil.LLVMInvokableTypeOf assemGen tyRef) 0u

        // TODO is this really the way to do this? maybe the types should be normalized on construction
        match getTypeKind (typeOf x.Value) with
        | TypeKind.IntegerTypeKind ->
            buildIntToPtr bldr x.Value ptrTy "invokablePtrFromInt"
        | TypeKind.PointerTypeKind ->
            buildBitCast bldr x.Value ptrTy "invokablePtr"
        | tk ->
            failwithf "cannot convert type kind %A to pointer" tk

    member x.AsTypeReference (assemGen:AssemGen, tyRef:TypeReference) =
        //let tyRef = tyRef.Resolve()
        let ty = toSaferType tyRef

        let noImpl () = failwithf "cannot convert as type reference %A" ty

        match ty with
        | Void -> noImpl ()
        | Boolean | Byte -> x.AsInt(false, PrimSizeBytes.One)
        | Char -> x.AsInt(false, PrimSizeBytes.Two)
        | UInt16 -> x.AsInt(false, PrimSizeBytes.Two)
        | SByte -> x.AsInt(true, PrimSizeBytes.One)
        | Int16 -> x.AsInt(true, PrimSizeBytes.Two)
        | Int32 -> x.AsInt(true, PrimSizeBytes.Four)
        | UInt32 -> x.AsInt(false, PrimSizeBytes.Four)
        | Int64 -> x.AsInt(true, PrimSizeBytes.Eight)
        | UInt64 -> x.AsInt(false, PrimSizeBytes.Eight)
        | Single -> x.AsFloat(true, false)
        | Double -> x.AsFloat(true, true)
        | String -> noImpl ()
        | Pointer _ptrTy -> value
        | ByReference _byRefType ->
            noImpl ()
            //pointerType assemGen.[byRefType.ElementType.FullName].InstanceVarsType 0u
        | ValueType _ | Class _ | Object ->
            match tyRefOpt with
            | None -> value
            | Some thisTyRef ->
                if isSameType thisTyRef tyRef then
                    value
                else
                    buildBitCast bldr value (pointerType assemGen.ClassMap.[tyRef].InstanceVarsType 0u) ""
        | Var _ -> noImpl ()
        | Array _arrTy -> value
        | GenericInstance _
        | TypedByReference
        | IntPtr -> x.AsNativeInt true
        | UIntPtr -> x.AsNativeInt false
        | FunctionPointer _
        | MVar _
        | RequiredModifier _
        | OptionalModifier _
        | Sentinel _
        | Pinned _ ->
            noImpl ()

    member x.AsStackType (asTy:StackType) =
        let cantConv () = failwithf "cannot convert %A to %A" ty asTy
        match asTy with
        | Int32_ST -> x.AsInt (false, PrimSizeBytes.Four)
        | Int64_ST -> x.AsInt (false, PrimSizeBytes.Eight)
        | NativeInt_ST -> x.AsNativeInt false
        | Float32_ST -> x.AsFloat(true, false)
        | Float64_ST -> x.AsFloat(true, true)
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
        | Int_ST ->
            if asSize = size then
                value
            elif asSize < size then
                buildTrunc bldr value (llvmIntTypeSized asSize) "truncInt"
            else
                let extFun = if asSigned then buildSExt else buildZExt
                extFun bldr value (llvmIntTypeSized asSize) "extendedInt"
        | Float_ST ->
            buildFPToSI bldr value (llvmIntTypeSized asSize) "truncatedFP"
        | ObjectRef_ST ->
            buildPtrToInt bldr value (llvmIntTypeSized asSize) "ptrAsInt"
        | _ ->
            failwithf "TODO implement int conversion for %A" ty

    member x.AsNativeInt (asSigned:bool) = x.AsInt (asSigned, nativeIntSize)

    member x.AsFloat (asSigned:bool, asLong:bool) =
        let asTy = if asLong then doubleType() else floatType()
        match ty with
        | Float32_ST ->
            if asLong
            then buildFPExt bldr value asTy "extendedFloat"
            else value
        | Float64_ST ->
            if asLong
            then value
            else buildFPTrunc bldr value asTy "truncFloat"
        | Int_ST ->
            if asSigned
            then buildSIToFP bldr value asTy "convVal"
            else buildUIToFP bldr value asTy "convVal"
        | _ -> failwithf "implicit cast from %A to float32 is not allowed" ty

    interface StackTyped with
        member x.StackType = ty

and TypeUtil () =

    static member LLVMVarTypeOf (assemGen : AssemGen) (ty : TypeReference) =

        let noImpl () = failwithf "no impl for %A type yet" ty
    
        match toSaferType ty with
        | Void -> voidType ()

        // TODO probably need a separate function for getting stack type vs normal type
        | Boolean -> int8Type ()
        | Char -> int16Type ()
        | SByte | Byte -> int8Type ()
        | Int16 | UInt16 -> noImpl ()
        | Int32 | UInt32 -> int32Type ()
        | Int64 | UInt64 -> int64Type ()
        | Single -> noImpl ()
        | Double -> doubleType ()
        | String -> noImpl ()
        | Pointer ptrTy ->
            pointerType assemGen.ClassMap.[ptrTy.ElementType].InstanceVarsType 0u
        | ByReference byRefType ->
            pointerType assemGen.ClassMap.[byRefType.ElementType].InstanceVarsType 0u
        | ValueType typeRef ->
            // TODO have no idea if this is right
            assemGen.ClassMap.[typeRef].InstanceVarsType
        | Class _ | Object ->
            pointerType assemGen.ClassMap.[ty].InstanceVarsType 0u
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
                    let elemTy = TypeUtil.LLVMVarTypeOf assemGen arrTy.ElementType
                    let basicArrTy = pointerType elemTy 0u
                    // FIXME array len should correspond to "native unsigned int" not int32
                    pointerType (structType [|int32Type (); basicArrTy|] false) 0u
                | lowerBound, upperBound ->
                    failwithf "dont know how to deal with given array shape yet %A->%A" lowerBound upperBound
            else
                failwithf "arrays of rank %i not yet implemented" arrTy.Rank
        | GenericInstance _
        | TypedByReference -> noImpl ()
        | IntPtr | UIntPtr -> llvmIntTypeSized nativeIntSize
        | FunctionPointer _
        | MVar _
        | RequiredModifier _
        | OptionalModifier _
        | Sentinel _
        | Pinned _ ->
            noImpl ()

    static member LLVMNewableTypeOf (assemGen : AssemGen) (ty : TypeReference) =

        let noImpl () = failwithf "no allocable type impl for %A type yet" ty

        match toSaferType ty with
        | Void -> voidType ()

        // TODO probably need a separate function for getting stack type vs normal type
        | Boolean -> int8Type ()
        | Char -> int16Type ()
        | SByte | Byte -> int8Type ()
        | Int16 | UInt16 -> noImpl ()
        | Int32 | UInt32 -> int32Type ()
        | Int64 | UInt64 -> int64Type ()
        | Single -> noImpl ()
        | Double -> doubleType ()
        | String -> noImpl ()
        | Pointer _ -> noImpl ()
        | ByReference _ -> noImpl ()
        | ValueType _ | Class _ | Object ->
            assemGen.ClassMap.[ty].InstanceVarsType
        | Var _ ->
            noImpl ()
        | Array _ ->
            noImpl ()
        | GenericInstance _
        | TypedByReference -> noImpl ()
        | IntPtr | UIntPtr -> llvmIntTypeSized nativeIntSize
        | FunctionPointer _
        | MVar _
        | RequiredModifier _
        | OptionalModifier _
        | Sentinel _
        | Pinned _ ->
            noImpl ()

    static member LLVMInvokableTypeOf (assemGen : AssemGen) (ty : TypeReference) =
        let newableTy = TypeUtil.LLVMNewableTypeOf assemGen ty
        pointerType newableTy 0u

and AssemGen (modRef : ModuleRef, assem : AssemblyDefinition) as x =
    let classMap = new ClassMap(modRef, x)

    member x.ClassMap : ClassMap = classMap

    member x.AssemDef : AssemblyDefinition = assem

and ClassMap (modRef : ModuleRef, assemGen : AssemGen) =
    let classDict = new Dictionary<string * string, ClassTypeRep>()

    member x.Item
        with get (tr : TypeReference) : ClassTypeRep =
            let td = tr.Resolve()
            let modName = td.Module.FullyQualifiedName

            // TODO make sure this addresses concerns mentioned in:
            // http://groups.google.com/group/mono-cecil/browse_thread/thread/2d59759860f31458
            let key = (modName, td.FullName)
            if classDict.ContainsKey key then
                classDict.[key]
            else
                let classTyRep = new ClassTypeRep(modRef, td, assemGen)
                classDict.[key] <- classTyRep
                classTyRep

    member x.Item
        with get (mr : MethodReference) : ClassTypeRep =
            x.[mr.Resolve().DeclaringType]

and ClassTypeRep (modRef : ModuleRef, typeDef : TypeDefinition, assemGen : AssemGen) as x =
    let structNamed name = structCreateNamed (getModuleContext modRef) name
    let staticRef = {
        new DefAndImpl<TypeRef>() with
            member x.Define() = structNamed (typeDef.FullName + "Static")
            member x.Implement vr =
                let staticFields =
                    [|for f in typeDef.StaticFields ->
                        TypeUtil.LLVMVarTypeOf assemGen f.FieldType|]
                structSetBody vr staticFields false
    }
    let instanceRef = {
        new DefAndImpl<TypeRef>() with
            member x.Define() = structNamed (typeDef.FullName + "Instance")
            member x.Implement vr =
                let instanceFields = [|
                    for f in typeDef.AllInstanceFields ->
                        TypeUtil.LLVMVarTypeOf assemGen f.FieldType
                |]
                structSetBody vr instanceFields false
    }
    let staticVars = lazy(addGlobal modRef staticRef.Value (typeDef.FullName + "Global"))
    let methMap = new MethodMap(modRef, assemGen, x)

    member x.InstanceVarsType = instanceRef.Value
    member x.StaticVarsType = staticRef.Value
    member x.StaticVars = staticVars.Force()
    member x.MethodMap : MethodMap = methMap
    member x.TypeDef : TypeDefinition = typeDef

and MethodMap (modRef : ModuleRef, assemGen : AssemGen, classRep : ClassTypeRep) =
    let methDict = new Dictionary<string * bool * string, MethodRep>()

    member x.Item
        with get (methRef : MethodReference) : MethodRep =
            let methDef = methRef.Resolve()

            if methDef.DeclaringType.FullName <> classRep.TypeDef.FullName then
                failwithf
                    "error looking up %s: method map for %s cannot be used to lookup a class from %s"
                    methDef.FullName
                    classRep.TypeDef.FullName
                    methDef.DeclaringType.FullName

            let modName = methDef.Module.FullyQualifiedName
            let key = (modName, methDef.IsStatic, methDef.FullName)
            if methDict.ContainsKey key then
                methDict.[key]
            else
                let methRep = new MethodRep(modRef, methDef, assemGen)
                methDict.[key] <- methRep
                methRep

and MethodRep (moduleRef : ModuleRef, methDef : MethodDefinition, assemGen : AssemGen) =
    
    let makeNewObj (bldr : BuilderRef) (methRef : MethodReference) (args : StackItem list) =
        // TODO implement GC along with object/class initialization code
        // FIXME naming is all screwed up! fix it
        let methDef = methRef.Resolve ()
        if not methDef.IsConstructor then
            failwith "expected a .ctor here"
        else
            let funRef = assemGen.ClassMap.[methDef].MethodMap.[methDef].ValueRef
            let llvmTy = assemGen.ClassMap.[methDef.DeclaringType].InstanceVarsType
            let newObj = buildMalloc bldr llvmTy ("new" + methDef.DeclaringType.FullName)
            let stackItemToArg (i:int) (item:StackItem) =
                item.AsTypeReference(assemGen, methDef.AllParameters.[i].ParameterType)
            let args = newObj :: List.mapi stackItemToArg args
            buildCall bldr funRef (Array.ofList args) "" |> ignore
            let ty =
                if methDef.DeclaringType.IsValueType then
                    new PointerType(methDef.DeclaringType) :> TypeReference
                else
                    methDef.DeclaringType :> TypeReference
            StackItem.StackItemFromAny(bldr, newObj, ty)

    let rec genInstructions
            (bldr : BuilderRef)
            (methodVal : ValueRef)
            (args : ValueRef array)
            (locals : ValueRef array)
            (blockMap : Map<int, BasicBlockRef>)
            (ilBB : BasicBlock)
            (stackVals : StackItem list)
            (insts : AnnotatedInstruction list) =
    
        if not ilBB.InitStackTypes.IsEmpty then
            failwith "no impl yet for basic blocks with non-empty init stack states"

        match insts with
        | [] -> ()
        | inst :: instTail ->
            //printfn "Inst: %A" inst.Instruction

            let poppedStack, stackTail = inst.PopTypes stackVals
            let pushTypes =
                match inst.TypesToPush poppedStack with
                | Some pushTypes -> pushTypes
                | None -> []
            let pushType () =
                match pushTypes with
                | [tyToPush] -> tyToPush
                | tysToPush -> failwithf "expected exactly one type to push but got %A" tysToPush

            let goNext (stackVals : StackItem list) =
                genInstructions bldr methodVal args locals blockMap ilBB stackVals instTail
            let goNextStackItem (si : StackItem) =
                goNext (si :: stackTail)
            let goNextValRef (value : ValueRef) (tyRefOpt : TypeReference option) =
                goNextStackItem (new StackItem(bldr, value, pushType(), tyRefOpt))

            let noImpl () = failwithf "instruction <<%A>> not implemented" inst.Instruction
            let unexpPush () = failwithf "unexpected push types <<%A>> for instruction <<%A>>" pushType inst.Instruction
            let unexpPop () = failwithf "unexpected pop types <<%A>> for instruction <<%A>>" poppedStack inst.Instruction

            match inst.Instruction with
            // Basic
            | Add ->
                // The add instruction adds value2 to value1 and pushes the result
                // on the stack. Overflow is not detected for integral operations
                // (but see add.ovf); floating-point overflow returns +inf or -inf.
                match poppedStack with
                | [value2; value1] ->
                    let v1 = value1.AsStackType(pushType())
                    let v2 = value2.AsStackType(pushType())
                    let addResult =
                        match pushType() with
                        | Float_ST -> buildFAdd bldr v1 v2 "tmpFAdd"
                        | Int_ST -> buildAdd bldr v1 v2 "tmpAdd"
                        | _ -> unexpPush()
                    goNextValRef addResult None
                | _ -> unexpPop()

            | AddOvf -> noImpl ()
            | AddOvfUn -> noImpl ()
            | And -> noImpl ()
            | Div ->
                match poppedStack with
                | [value2; value1] ->
                    let v1 = value1.AsStackType (pushType())
                    let v2 = value2.AsStackType (pushType())
                    let divResult =
                        match pushType() with
                        | Float_ST -> buildFDiv bldr v1 v2 "tmpFDiv"
                        | Int_ST -> buildSDiv bldr v1 v2 "tmpDiv"
                        | _ -> unexpPush()
                    goNextValRef divResult None
                | _ -> unexpPop()

            | DivUn -> noImpl ()
            | Ceq -> noImpl ()
            | Cgt -> noImpl ()
            | CgtUn -> noImpl ()
            | Clt -> noImpl ()
            | CltUn -> noImpl ()

            // For conversion ops see ECMA-335 Partition III 1.5 table 8
            | ConvI1 -> noImpl ()
            | ConvI2 ->
                noImpl ()
            | ConvI4 ->
                match poppedStack with
                | [STyped Int_ST as value] ->
                    goNextValRef (value.AsInt(true, PrimSizeBytes.Four)) None
                | _ ->
                    failwithf "convi4 no impl for <<%A>>" [for x in poppedStack -> (x :> StackTyped).StackType]
            | ConvI8 -> noImpl ()
            | ConvR4 ->
                noImpl ()
            | ConvR8 ->
                match poppedStack with
                | [value] -> goNextValRef (value.AsFloat(true, true)) None
                | _ -> noImpl()

            | ConvU4 -> noImpl ()
            | ConvU8 -> noImpl ()
            | ConvU2 -> noImpl ()
            | ConvU1 -> noImpl ()
            | ConvI ->
                match poppedStack with
                | [value] -> goNextValRef (value.AsNativeInt true) None
                | _ -> noImpl()

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
                match poppedStack with
                | [value2; value1] ->
                    let v1 = value1.AsStackType(pushType())
                    let v2 = value2.AsStackType(pushType())
                    let mulResult =
                        match pushType() with
                        | Float_ST -> buildFMul bldr v1 v2 "tmpFMul"
                        | Int_ST -> buildMul bldr v1 v2 "tmpMul"
                        | _ -> unexpPush()
                    goNextValRef mulResult None
                | _ -> unexpPop()

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
                match poppedStack with
                | [value2; value1] ->
                    let v1 = value1.AsStackType(pushType())
                    let v2 = value2.AsStackType(pushType())
                    let subResult =
                        match pushType() with
                        | Float_ST -> buildFSub bldr v1 v2 "tmpFSub"
                        | Int_ST -> buildSub bldr v1 v2 "tmpSub"
                        | _ -> unexpPush()
                    goNextValRef subResult None
                | _ -> unexpPop()

            | SubOvf -> noImpl ()
            | SubOvfUn -> noImpl ()
            | Xor -> noImpl ()
            | Or -> noImpl ()
            | Neg -> noImpl ()
            | Not -> noImpl ()
            | Ldnull -> noImpl ()
            | Dup ->
                // TODO this will probably only work in some limited cases
                match poppedStack with
                | [value] -> goNext (value :: value :: stackTail)
                | _ -> unexpPop()

            | Pop ->
                match poppedStack with
                | [_] -> goNext stackTail
                | _ -> unexpPop()

            | Ckfinite -> noImpl ()
            | Nop ->
                match poppedStack with
                | [] -> goNext stackVals
                | _ -> unexpPop()
            | LdcI4 i ->
                let constResult = constInt (int32Type ()) (uint64 i) false // TODO correct me!!
                goNextValRef constResult None
            | LdcI8 i ->
                let constResult = constInt (int64Type ()) (uint64 i) false // TODO correct me!!
                goNextValRef constResult None
            | LdcR4 _ -> noImpl ()
            | LdcR8 r ->
                let constResult = constReal (doubleType ()) r
                goNextValRef constResult None
            | Ldarg paramDef ->
                let name = "tmp_" + paramDef.Name
                let value = buildLoad bldr args.[paramDef.Sequence] name
                goNextStackItem (StackItem.StackItemFromAny(bldr, value, paramDef.ParameterType))

            | Ldarga paramDef ->
                goNextValRef args.[paramDef.Sequence] (Some paramDef.ParameterType)
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
                goNextStackItem (StackItem.StackItemFromAny(bldr, loadResult, varDef.VariableType))
            | Ldloca varDef ->
                goNextValRef locals.[varDef.Index] None
            | Starg paramDef ->
                match poppedStack with
                | [stackHead] ->
                    let valRef = stackHead.AsTypeReference(assemGen, paramDef.ParameterType)
                    buildStore bldr valRef args.[paramDef.Sequence] |> ignore
                    goNext stackTail
                | _ -> unexpPop()
            | StindRef _ -> noImpl ()
            | StindI1 _ -> noImpl ()
            | StindI2 _ -> noImpl ()
            | StindI4 _ -> noImpl ()
            | StindI8 _ -> noImpl ()
            | StindR4 _ -> noImpl ()
            | StindR8 _ -> noImpl ()
            | StindI _ -> noImpl ()
            | Stloc varDef ->
                match poppedStack with
                | [stackHead] ->
                    let valRef = stackHead.AsTypeReference(assemGen, varDef.VariableType)
                    buildStore bldr valRef locals.[varDef.Index] |> ignore
                    goNext stackTail
                | _ -> unexpPop()

            // Control transfer
            | Br bb ->
                buildBr bldr blockMap.[bb.OffsetBytes] |> ignore
            | Jmp _ ->
                noImpl ()
            | Brfalse (zeroBB, nonZeroBB) | Brtrue (nonZeroBB, zeroBB) ->
                match poppedStack with
                | [value] ->
                    // TODO would be more efficient to have custom test per size
                    let valToTest = value.AsInt(false, PrimSizeBytes.Eight)
                    let zero = constInt (int64Type()) 0uL false
                    let isZero = buildICmp bldr IntPredicate.IntEQ valToTest zero "isZero"
                    let nonZeroBlk = blockMap.[nonZeroBB.OffsetBytes]
                    let zeroBlk = blockMap.[zeroBB.OffsetBytes]
                    buildCondBr bldr isZero zeroBlk nonZeroBlk |> ignore
                | _ ->
                    failwithf "expected a single value to be popped from the stack for: %A" inst
                    
            | Beq (ifBB, elseBB) | Bge (ifBB, elseBB) | Bgt (ifBB, elseBB)
            | Ble (ifBB, elseBB) | Blt (ifBB, elseBB) | BneUn (ifBB, elseBB)
            | BgeUn (ifBB, elseBB) | BgtUn (ifBB, elseBB) | BleUn (ifBB, elseBB)
            | BltUn (ifBB, elseBB) ->
            
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a branch"
            
                let isSigned () =
                    match inst.Instruction with
                    | BneUn _ | BgeUn _ | BgtUn _ | BleUn _ | BltUn _ ->
                        false
                    | _ ->
                        true

                let brInt i1 i2 =
                    let brWith op =
                        let brTest = buildICmp bldr op i1 i2 "brTest"
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
                    | _         -> failwith "whoa! this error should be impossible!"

                match poppedStack with
                | [STyped NativeInt_ST as value2; (STyped NativeInt_ST | STyped Int32_ST) as value1]
                | [(STyped NativeInt_ST | STyped Int32_ST) as value2; STyped NativeInt_ST as value1] ->
                    let i1 = value1.AsNativeInt(isSigned())
                    let i2 = value2.AsNativeInt(isSigned())
                    brInt i1 i2
                | [STyped Int32_ST as value2; STyped Int32_ST as value1]
                | [STyped Int64_ST as value2; STyped Int64_ST as value1] ->
                    brInt value1.Value value2.Value
                | _ ->
                    failwithf "branching not yet implemented for types: %A" [for x in poppedStack -> (x :> StackTyped).StackType]

            | Switch (caseBlocks, defaultBlock) ->
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a branch"
            
                match poppedStack with
                | [value] ->
                    let caseInts =
                        [|for i in 0 .. caseBlocks.Length - 1 ->
                            constInt (int32Type ()) (uint64 i) false|]
                    let caseBlocks = [|for b in caseBlocks -> blockMap.[b.OffsetBytes]|]
                    let target = value.AsInt(false, PrimSizeBytes.Four)
                    buildSwitchWithCases bldr target (Array.zip caseInts caseBlocks) blockMap.[defaultBlock.OffsetBytes]
                | _ ->
                    unexpPop()

            | Ret ->
                // The evaluation stack for the current method shall be empty except for the value to be returned.
                if not stackTail.IsEmpty then
                    failwith "the value stack should be empty after a return"
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a return"

                match poppedStack with
                | [] ->
                    if toSaferType methDef.ReturnType <> Void then
                        failwith "expected a void return type"
                    buildRetVoid bldr |> ignore
                | [stackHead] ->
                    let retItem = stackHead.AsTypeReference(assemGen, methDef.ReturnType)
                    buildRet bldr retItem |> ignore
                | _ ->
                    unexpPop()

            // Method call
            | Call (tailCall, methRef) ->
                // look up the corresponding LLVM function
                let methDef = methRef.Resolve()
                let funRef = assemGen.ClassMap.[methDef].MethodMap.[methDef].ValueRef

                let stackItemToArg (i:int) (item:StackItem) =
                    item.AsTypeReference(assemGen, methDef.AllParameters.[i].ParameterType)
                let args = List.mapi stackItemToArg (List.rev poppedStack)
                let resultName = if pushTypes.IsEmpty then "" else "callResult"
                let callResult = buildCall bldr funRef (Array.ofList args) resultName
                if tailCall then setTailCall callResult true
                if pushTypes.IsEmpty then
                    goNext stackTail
                else
                    goNextStackItem (StackItem.StackItemFromAny(bldr, callResult, methRef.ReturnType))

            | Callvirt _ -> noImpl ()
            | Calli _ -> noImpl ()
            | Ldftn _ -> noImpl ()
            | Newobj methRef -> makeNewObj bldr methRef (List.rev poppedStack) |> goNextStackItem

            // Exceptions
            | Throw -> noImpl ()
            | Endfinally -> noImpl ()
            | Endfilter -> noImpl ()
            | Leave _ -> noImpl ()
            | Rethrow -> noImpl ()

            // Object instructions
            | Ldsfld (_volatilePrefix, fieldRef) ->
                match poppedStack with
                | [] ->
                    // TODO alignment and volitility
                    let fieldName = fieldRef.FullName
                    let declaringTy = fieldRef.DeclaringType.Resolve ()
                    let staticCilFields = (fieldRef.DeclaringType.Resolve ()).StaticFields
                    let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) staticCilFields

                    // OK now we need to load the field
                    let declClassRep = assemGen.ClassMap.[declaringTy]
                    let fieldPtr = buildStructGEP bldr declClassRep.StaticVars (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                    let fieldValue = buildLoad bldr fieldPtr (fieldRef.Name + "Value")
                    let fieldStackItem = StackItem.StackItemFromAny(bldr, fieldValue, fieldRef.FieldType)
                    goNextStackItem fieldStackItem
                | _ ->
                    unexpPop()

            | Ldfld (_unalignedPrefix, _volatilePrefix, fieldRef) ->
                match poppedStack with
                | [selfPtr] ->
                    // TODO alignment and volitility
                    let fieldName = fieldRef.FullName
                    let decTy = fieldRef.DeclaringType.Resolve()
                    let cilFields = decTy.InstanceFields
                    // TODO maybe RVA or MetadataToken is better than FullName
                    let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) cilFields
                    let fieldIndex = fieldIndex + decTy.NumInheritedInstanceFields

                    // OK now we need to load the field
                    // TODO this doesn't seem to work. Figure out why
                    //let selfPtrVal = selfPtr.AsPointerTo(assemGen, decTy)
                    let selfPtrVal = selfPtr.Value
                    let fieldPtr = buildStructGEP bldr selfPtrVal (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                    let fieldValue = buildLoad bldr fieldPtr (fieldRef.Name + "Value")
                    let fieldStackItem = StackItem.StackItemFromAny(bldr, fieldValue, fieldRef.FieldType)
                    goNextStackItem fieldStackItem
                | _ ->
                    unexpPop()

            | Ldsflda _ -> noImpl ()
            | Ldflda _ -> noImpl ()
            | Stsfld (_volatilePrefix, fieldRef) ->
                match poppedStack with
                | [value] ->
                    // TODO volatility
                    let fieldName = fieldRef.FullName
                    let declaringTy = fieldRef.DeclaringType.Resolve ()
                    let staticCilFields = declaringTy.StaticFields
                    let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) staticCilFields

                    // now store the field
                    let declClassRep = assemGen.ClassMap.[declaringTy]
                    let fieldPtr = buildStructGEP bldr declClassRep.StaticVars (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                    buildStore bldr (value.AsTypeReference(assemGen, fieldRef.FieldType)) fieldPtr |> ignore
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Stfld (_unalignedPrefix, _volatilePrefix, fieldRef) ->
                match poppedStack with
                | [value; selfPtr] ->
                    // TODO alignment and volitility
                    let fieldName = fieldRef.FullName
                    let decTy = fieldRef.DeclaringType.Resolve()
                    let cilFields = decTy.InstanceFields
                    let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) cilFields
                    let fieldIndex = fieldIndex + decTy.NumInheritedInstanceFields

                    // OK now we need to store the field
                    let fieldPtr = buildStructGEP bldr selfPtr.Value (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                    buildStore bldr (value.AsTypeReference(assemGen, fieldRef.FieldType)) fieldPtr |> ignore
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Ldstr _ -> noImpl ()
            | Isinst _ -> noImpl ()
            | Castclass _ -> noImpl ()
            | Ldtoken tokProvider ->
                match tokProvider with
                | :? FieldReference as fr ->
                    let corelibName = assemGen.AssemDef.MainModule.TypeSystem.Corlib.Name
                    let corelib = assemGen.AssemDef.MainModule.AssemblyResolver.Resolve corelibName
                    let allCorelibTys = seq {for m in corelib.Modules do yield! m.Types}
                    let isRunFieldHdl (t : TypeDefinition) =
                        t.FullName = "System.RuntimeFieldHandle"
                    match Seq.tryFind isRunFieldHdl allCorelibTys with
                    | None -> failwithf "failed to locate System.RuntimeFieldHandle in %s" corelibName
                    | Some td ->
                        let isCtor (md : MethodDefinition) =
                            md.IsConstructor && Seq.length md.Parameters = 1 && (
                                match toSaferType (Seq.head md.Parameters).ParameterType with
                                | IntPtr -> true
                                | _ -> false
                            )
                        match Seq.tryFind isCtor td.Methods with
                        | Some md ->
                            let fieldID = 0uL
                            let fieldIDVal = constInt (llvmIntTypeSized nativeIntSize) fieldID false
                            let fieldIDStackItem = new StackItem(bldr, fieldIDVal, StackType.NativeInt_ST, None)
                            let objStackItem = makeNewObj bldr md [fieldIDStackItem]
                            goNextStackItem objStackItem
                        | None -> failwith "failed to find constructor for runtime field handle"

                | _ ->
                    failwithf "no code to deal with tokProvider of type %s" (tokProvider.GetType().FullName)
                failwith "load tok"
            | Ldvirtftn _ -> noImpl ()

            // Value type instructions
            | Cpobj _ -> noImpl ()
            | Initobj _ -> noImpl ()
            | Ldobj (_unalignedPrefix, volatilePrefix, tyRef) ->
                // TODO deal with unaligned
                match poppedStack with
                | [src] ->
                    // TODO FIXME leaking memory here also this impl is probably wrong for many types
                    let cpTy = TypeUtil.LLVMNewableTypeOf assemGen tyRef
                    let dest = buildMalloc bldr cpTy "ldobj_copy_dest"
                    // TODO does this take care of volatile requirement?
                    buildCopy moduleRef bldr dest (src.AsTypeReference(assemGen, tyRef)) volatilePrefix
                    let castTy = pointerType cpTy 0u
                    let destCast = buildBitCast bldr dest castTy "ldobj_copy_dest_cast"
                    // TODO is this load always right?? it seems strange but it works for now
                    let destLoad = buildLoad bldr destCast "ldobj_load_dest"
                    goNextValRef destLoad (Some tyRef)
                | _ ->
                    unexpPop()

            | Stobj (_unalignedPrefix, volatilePrefix, tyRef) ->
                // TODO deal with unaligned
                match poppedStack with
                | [src; dest] ->
                    if tyRef.IsPrimitive then
                        // TODO volatile?
                        let srcPrim = src.AsTypeReference(assemGen, tyRef)
                        let destPtr = dest.AsPointerTo(assemGen, tyRef)
                        buildStore bldr srcPrim destPtr |> ignore
                    else
                        let srcVal = src.AsTypeReference(assemGen, tyRef)
                        // TODO does this take care of volatile requirement?
                        buildCopy moduleRef bldr dest.Value srcVal volatilePrefix
                    goNext stackTail
                | _ ->
                    unexpPop()
            | Box _ -> noImpl ()
            | Unbox _ -> noImpl ()
            | UnboxAny _ -> noImpl ()
            | Sizeof tyRef ->
                let size =
                    match toSaferType tyRef with
                    | Boolean | Byte | SByte ->
                        1uL
                    | Char | UInt16 | Int16 ->
                        2uL
                    | Int32 | UInt32 | Single ->
                        4uL
                    | Int64 | UInt64 | Double ->
                        8uL
                    | Pointer _ | IntPtr | UIntPtr ->
                        uint64 nativeIntSize
                    | Void
                    | String
                    | ByReference _
                    | ValueType _
                    | Class _
                    | Object
                    | Var _
                    | Array _
                    | GenericInstance _
                    | TypedByReference
                    | FunctionPointer _
                    | MVar _
                    | RequiredModifier _
                    | OptionalModifier _
                    | Sentinel _
                    | Pinned _ ->
                        noImpl()

                goNextValRef (constInt (int32Type()) size false) None

            // Generalized array instructions. In AbsIL these instructions include
            // both the single-dimensional variants (with ILArrayShape == ILArrayShape.SingleDimensional)
            // and calls to the "special" multi-dimensional "methods" such as
            //   newobj void string[,]::.ctor(int32, int32)
            //   call string string[,]::Get(int32, int32)
            //   call string& string[,]::Address(int32, int32)
            //   call void string[,]::Set(int32, int32,string)
            | Ldelem elemTyRef ->
                match poppedStack with
                | [index; arrObj] ->
                    let arrPtrAddr = buildStructGEP bldr arrObj.Value 1u "arrPtrAddr"
                    let arrPtr = buildLoad bldr arrPtrAddr "arrPtr"
                    // TODO: make sure that index.Value is good here... will work for all native ints or int32's
                    let elemAddr = buildGEP bldr arrPtr [|index.Value|] "elemAddr"
                    let elem = buildLoad bldr elemAddr "elem"

                    goNextStackItem (StackItem.StackItemFromAny(bldr, elem, elemTyRef))
                | _ ->
                    unexpPop()
            | Stelem elemTyRef ->
                match poppedStack with
                | [value; index; arrObj] ->
                    let arrPtrAddr = buildStructGEP bldr arrObj.Value 1u "arrPtrAddr"
                    let arrPtr = buildLoad bldr arrPtrAddr "arrPtr"
                    // TODO: make sure that index.Value is good here... will work for all native ints or int32's
                    let elemAddr = buildGEP bldr arrPtr [|index.Value|] "elemAddr"
                    buildStore bldr (value.AsTypeReference(assemGen, elemTyRef)) elemAddr |> ignore

                    goNext stackTail
                | _ ->
                    unexpPop()
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
                match poppedStack with
                | [numElems] ->
                    // allocate the array to the heap
                    // TODO it seems pretty lame to have this code here. need to think
                    // about how this should really be structured
                    let elemTy = TypeUtil.LLVMVarTypeOf assemGen elemTypeRef
                    // TODO: make sure that numElems.Value is good here... will work for all native ints or int32's
                    let newArr = buildArrayMalloc bldr elemTy numElems.Value ("new" + elemTypeRef.Name + "Arr")

                    // TODO I think we have to initialize the arrays

                    let basicArrTy = pointerType elemTy 0u
                    // FIXME array len should correspond to "native unsigned int" not int32
                    let arrObjTy = structType [|int32Type (); basicArrTy|] false
                    let newArrObj = buildMalloc bldr arrObjTy ("new" + elemTypeRef.Name + "ArrObj")

                    // fill in the array object
                    let lenAddr = buildStructGEP bldr newArrObj 0u "lenAddr"
                    // TODO: make sure that numElems.Value is good here... will work for all native ints or int32's
                    buildStore bldr numElems.Value lenAddr |> ignore
                    let arrPtrAddr = buildStructGEP bldr newArrObj 1u "arrPtrAddr"
                    buildStore bldr newArr arrPtrAddr |> ignore

                    // TODO "None" may be the wrong thing to do here
                    goNextValRef newArrObj None
                | _ ->
                    unexpPop()
            | Ldlen ->
                match poppedStack with
                | [arrObj] ->
                    let lenAddr = buildStructGEP bldr arrObj.Value 0u "lenAddr"
                    goNextValRef (buildLoad bldr lenAddr "len") None
                | _ ->
                    unexpPop()

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

    let genAlloca (bldr : BuilderRef) (t : TypeReference) (name : string) =
        buildAlloca bldr (TypeUtil.LLVMVarTypeOf assemGen t) (name + "Alloca")

    let genLocal (bldr : BuilderRef) (l : VariableDefinition) =
        genAlloca bldr l.VariableType (nameOrDefault l.Name "local")

    let genParam (bldr : BuilderRef) (p : ParameterDefinition) =
        genAlloca bldr p.ParameterType (nameOrDefault p.Name "param")

    let genMethodBody (methodVal : ValueRef) =

        //printfn "genMethodBody for: %s" methDef.FullName

        // create the entry block
        use bldr = new Builder(appendBasicBlock methodVal "entry")
        let args = Array.map (genParam bldr) methDef.AllParameters
        for i = 0 to args.Length - 1 do
            buildStore bldr (getParam methodVal (uint32 i)) args.[i] |> ignore
        let locals = Array.map (genLocal bldr) (Array.ofSeq methDef.Body.Variables)
        let blocks = methDef.Body.BasicBlocks
        let blockDecs =
            [for b in blocks do
                let blockName = "block_" + string b.OffsetBytes
                yield (b.OffsetBytes, appendBasicBlock methodVal blockName)]
        match blockDecs with
        | [] -> failwith ("empty method body: " + methDef.FullName)
        | (_, fstBlockDec) :: _ ->
            buildBr bldr fstBlockDec |> ignore
            let blockMap = Map.ofList blockDecs
            for i in 0 .. blocks.Length - 1 do
                if not blocks.[i].InitStackTypes.IsEmpty then
                    failwith "don't yet know how to deal with non empty basic blocks!!"
                use bldr = new Builder(blockMap.[blocks.[i].OffsetBytes])
                genInstructions
                    bldr
                    methodVal
                    args
                    locals
                    blockMap
                    blocks.[i]
                    []
                    blocks.[i].Instructions

    let declareMethodDef () =

        let nameFunParam (fn : ValueRef) (i : int) (p : ParameterDefinition) =
            let llvmParam = getParam fn (uint32 i)
            let name = nameOrDefault p.Name ("arg" + string i)
            setValueName llvmParam name

        if methDef.HasBody then
            let paramTys = [|for p in methDef.AllParameters -> TypeUtil.LLVMVarTypeOf assemGen p.ParameterType|]
            let retTy = TypeUtil.LLVMVarTypeOf assemGen methDef.ReturnType
            let funcTy = functionType retTy paramTys
            let fnName = if methDef.Name = "main" then "_main" else methDef.Name
            let fn = addFunction moduleRef fnName funcTy
        
            Array.iteri (nameFunParam fn) methDef.AllParameters
        
            fn
        elif methDef.IsInternalCall then
            failwith "wo wo wo wo... it's an internal call"
        elif methDef.HasPInvokeInfo then
            let pInv = methDef.PInvokeInfo

            // TODO for now assuming that we don't need to use "dlopen"
            if pInv.Module.Name <> "libc.dll" then
                failwith "sorry! only works with libc for now. No dlopen etc."

            let paramTys = [|for p in methDef.Parameters -> TypeUtil.LLVMVarTypeOf assemGen p.ParameterType|]
            let retTy = TypeUtil.LLVMVarTypeOf assemGen methDef.ReturnType
            let funcTy = functionType retTy paramTys
            let fn = addFunction moduleRef pInv.EntryPoint funcTy
            setLinkage fn Linkage.ExternalLinkage

            Seq.iteri (nameFunParam fn) methDef.Parameters

            fn
        else
            failwith "don't know how to declare method without a body"

    let valueRef = {
        new DefAndImpl<ValueRef>() with
            member x.Define() = declareMethodDef ()
            member x.Implement vr = if methDef.HasBody then genMethodBody vr
    }

    member x.ValueRef = valueRef.Value

let genMainFunction
        (assemGen : AssemGen)
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
        | [||] ->
            let valRef = assemGen.ClassMap.[methDef].MethodMap.[methDef].ValueRef
            buildCall bldr valRef [||] resultName
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

let genTypeDefs (llvmModuleRef : ModuleRef) (assem : AssemblyDefinition) =

    let assemGen = new AssemGen(llvmModuleRef, assem)

    // force evaluation of all module types
    let rec goTypeDef (td : TypeDefinition) =
        let classRep = assemGen.ClassMap.[td]
        for m in td.Methods do
            classRep.MethodMap.[m].ValueRef |> ignore
        Seq.iter goTypeDef td.NestedTypes
    Seq.iter goTypeDef assem.MainModule.Types

    match assem.EntryPoint with
    | null -> ()
    | methDef -> genMainFunction assemGen methDef llvmModuleRef
