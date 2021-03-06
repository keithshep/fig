module Fig.LLVMCodeGen

module FAP = Fig.AssemblyParser
module FPC = Fig.ParseCode

module LC = LLVM.Core
module LGC = LLVM.Generated.Core

type Dict<'k, 'v> = System.Collections.Generic.Dictionary<'k, 'v>
type WorkQueue = System.Collections.Generic.Queue<unit -> unit>

type Inst = FAP.AbstInst
type TyBlob = FAP.TypeBlob
type StackType = FAP.StackType

// an active patter that takes a parameter and extracts the TypeBlob
// when there are no custom mods
let (|SimplePTy|OtherPTy|) (p:FAP.Parameter) =
    match p.Type with
    | {FAP.Param.customMods=[]; FAP.Param.pType=FAP.MayByRefTy mayByTy} ->
        if mayByTy.isByRef then
            OtherPTy
        else
            SimplePTy mayByTy.ty
    | _ ->
        OtherPTy

let tyBlobEqTy (mscorlib:FAP.MscorlibAssembly) (ty:FAP.TypeDefRefOrSpec) (tb:TyBlob) : bool =
    let doTest (otherTy:FAP.TypeDef) =
        match ty with
        | :? FAP.TypeDefOrRef as ty ->
            ty.Resolve() = otherTy
        | _ ->
            false

    match tb with
    | TyBlob.Object -> doTest mscorlib.ObjectTypeDef
    | TyBlob.String -> doTest mscorlib.StringTypeDef
    | TyBlob.Class blobTy | TyBlob.ValueType blobTy ->
        match blobTy with
        | :? FAP.TypeDefOrRef as blobTy ->
            doTest(blobTy.Resolve())
        | _ ->
            false
    | _ ->
        false

let (|EqTy|) (mscorlib:FAP.MscorlibAssembly) (ty:FAP.TypeDefRefOrSpec) (tb:TyBlob) =
    if tyBlobEqTy mscorlib ty tb then
        EqTy true
    else
        EqTy false

let addAndInitGlobal (modRef:LGC.ModuleRef) (ty:LGC.TypeRef) (name:string) (initVal:LGC.ValueRef) : LGC.ValueRef =
    let globalVal = LGC.addGlobal modRef ty name
    LGC.setLinkage globalVal LGC.Linkage.InternalLinkage
    LGC.setInitializer globalVal initVal
    globalVal

let addAndZeroInitGlobal (modRef:LGC.ModuleRef) (ty:LGC.TypeRef) (name:string) : LGC.ValueRef =
    addAndInitGlobal modRef ty name (LGC.constNull ty)

type [<AbstractClass>] DefAndImpl<'T> (?wq:WorkQueue) =
    let mutable valueOpt = None : 'T option

    abstract member Define : unit -> 'T
    abstract member Implement : 'T -> unit

    member x.Value : 'T =
        match valueOpt with
        | Some value -> value
        | None ->
            let value = x.Define()
            valueOpt <- Some value

            match wq with
            | None ->
                x.Implement value
            | Some wq ->
                wq.Enqueue (fun () -> x.Implement value)

            value

type PrimSizeBytes = One = 1 | Two = 2 | Four = 4 | Eight = 8
let nativeIntSize = PrimSizeBytes.Eight

let int8Ty = LGC.int8Type()
let int16Ty = LGC.int16Type()
let int32Ty = LGC.int32Type()
let int64Ty = LGC.int64Type()
let nativeIntTy =
    match nativeIntSize with
    | PrimSizeBytes.Eight -> int64Ty
    | PrimSizeBytes.Four -> int32Ty
    | _ -> failwithf "invalid native int size: %A" nativeIntSize
let floatTy = LGC.floatType()
let doubleTy = LGC.doubleType()
let voidTy = LGC.voidType()

let sizeOfStackType = function
    | StackType.Int32_ST | StackType.Float32_ST ->
        PrimSizeBytes.Four
    | StackType.Int64_ST | StackType.Float64_ST ->
        PrimSizeBytes.Eight
    | StackType.NativeInt_ST | StackType.ObjectRef_ST | StackType.ManagedPointer_ST ->
        // TODO not sure about objectref... and what about value types?
        nativeIntSize

let llvmIntTypeSized = function
    | PrimSizeBytes.One -> int8Ty
    | PrimSizeBytes.Two -> int16Ty
    | PrimSizeBytes.Four -> int32Ty
    | PrimSizeBytes.Eight -> int64Ty
    | s -> failwithf "invalid primitive size given: %i" (int s)

let simpleTypeName (ty : FAP.TypeDefRefOrSpec) =
    match ty with
    | :? FAP.TypeDefOrRef as ty -> ty.Name
    | :? FAP.TypeSpec as ty ->
        match ty.TypeSpecBlob with
        | FAP.TypeSpecBlob.Array _ -> "Array"
        | FAP.TypeSpecBlob.FnPtr _ -> "FnPtr"
        | FAP.TypeSpecBlob.GenericInst _ -> "GenericInst"
        | FAP.TypeSpecBlob.MVar _ -> "MVar"
        | FAP.TypeSpecBlob.Ptr _ -> "Ptr"
        | FAP.TypeSpecBlob.SzArray _ -> "SzArray"
        | FAP.TypeSpecBlob.Var _ -> "Var"
    | _ ->
        failwithf "typeSimpleName: unexpected type %s" (ty.GetType().Name)

type CodeGenUtil =
    static member MakeNewArray (assemGen:AssemGen) (bldr:LGC.BuilderRef) (elemTypeRef:FAP.TypeDefRefOrSpec) (numElemsValRef:LGC.ValueRef) =
        // TODO should this be changed to signed??? I think not
        //let numElemsValRef = numElems.AsNativeInt false

        // allocate the array to the heap
        // TODO it seems pretty lame to have this code here. need to think
        // about how this should really be structured
        let elemTy = TypeUtil.LLVMVarTypeOf assemGen elemTypeRef
        // TODO: make sure that numElems.Value is good here... will work for all native ints or int32's
        let elemTypeName = simpleTypeName elemTypeRef
        let newArr = LGC.buildArrayMalloc bldr elemTy numElemsValRef ("new" + elemTypeName + "Arr")

        // TODO I think we have to initialize the arrays

        let basicArrTy = LGC.pointerType elemTy 0u
        let arrObjTy = LC.structType [|nativeIntTy; basicArrTy|] false
        let newArrObj = LGC.buildMalloc bldr arrObjTy ("new" + elemTypeName + "ArrObj")

        // fill in the array object
        let lenAddr = LGC.buildStructGEP bldr newArrObj 0u "lenAddr"
        LGC.buildStore bldr numElemsValRef lenAddr |> ignore
        let arrPtrAddr = LGC.buildStructGEP bldr newArrObj 1u "arrPtrAddr"
        LGC.buildStore bldr newArr arrPtrAddr |> ignore

        let arrTy =
            match elemTypeRef.AsTypeBlob() with
            | None -> failwith "failed to convert array element type into a type"
            | Some ty -> TyBlob.SzArrayOf ty

        //StackItem.FromTypeBlob bldr newArrObj arrTy
        (arrTy, newArrObj)

and TypeUtil =
    static member LLVMVarTypeOfTypeBlob (assemGen : AssemGen) (tyBlob : TyBlob) : LGC.TypeRef =
        let noImpl() = failwithf "LLVMVarTypeOfTypeBlob: no impl for %A type yet" tyBlob
        let ptrTo (ty:FAP.TypeDefRefOrSpec) : LGC.TypeRef =
            LGC.pointerType (assemGen.GetTypeRep(ty).InstanceVarsType) 0u

        match tyBlob with
        | FAP.TypeBlob.Boolean -> int8Ty
        | FAP.TypeBlob.Char -> int16Ty
        | FAP.TypeBlob.I1 | FAP.TypeBlob.U1 -> int8Ty
        | FAP.TypeBlob.I2 | FAP.TypeBlob.U2 -> noImpl()
        | FAP.TypeBlob.I4 | FAP.TypeBlob.U4 -> int32Ty
        | FAP.TypeBlob.I8 | FAP.TypeBlob.U8 -> int64Ty
        | FAP.TypeBlob.R4 -> noImpl()
        | FAP.TypeBlob.R8 -> doubleTy
        | FAP.TypeBlob.I | FAP.TypeBlob.U -> llvmIntTypeSized nativeIntSize
        | FAP.TypeBlob.Class ty | FAP.TypeBlob.ValueType ty -> ptrTo ty
        | FAP.TypeBlob.MVar _ -> noImpl()
        | FAP.TypeBlob.Object -> ptrTo assemGen.Mscorlib.ObjectTypeDef
        | FAP.TypeBlob.String -> ptrTo assemGen.Mscorlib.StringTypeDef
        | FAP.TypeBlob.Var _ -> noImpl()

        // the following are also in type spec
        | FAP.TypeBlob.Ptr (custMods, tyOpt) ->
            if not custMods.IsEmpty then
                noImpl()
            match tyOpt with
            | None -> noImpl()
            | Some ty ->
                let llvmTyOfPointee = TypeUtil.LLVMVarTypeOfTypeBlob assemGen ty
                match ty with
                | TyBlob.Object | TyBlob.Class _ | TyBlob.ValueType _ ->
                    // objects and complex valuetypes are implemented as pointers already
                    llvmTyOfPointee
                | _ ->
                    LGC.pointerType llvmTyOfPointee 0u
        | FAP.TypeBlob.FnPtr _ -> noImpl()
        | FAP.TypeBlob.Array (ty, arrShape) -> noImpl()
        | FAP.TypeBlob.SzArray (custMods, elemTyBlob) ->
            if not custMods.IsEmpty then
                noImpl()

            // LLVM docs say:
            // "... 'variable sized array' addressing can be implemented in LLVM
            // with a zero length array type". So, we implement this as a struct
            // which contains a length element and an array element
            let elemTy = TypeUtil.LLVMVarTypeOfTypeBlob assemGen elemTyBlob
            let basicArrTy = LGC.pointerType elemTy 0u

            // FIXME array len should correspond to "native unsigned int" not int32
            LGC.pointerType (LC.structType [|nativeIntTy; basicArrTy|] false) 0u

        // GenericInst bool isClass with false indicating valuetype
        | FAP.TypeBlob.GenericInst _ -> noImpl()

    static member LLVMVarTypeOf (assemGen : AssemGen) (ty : FAP.TypeDefRefOrSpec) =
        let noImpl() = failwithf "LLVMVarTypeOf: no impl for %A yet" ty

        match ty with
        | :? FAP.TypeDefOrRef as ty ->
            match ty.AsTypeBlob() (*false*) with
            | Some tyBlob -> TypeUtil.LLVMVarTypeOfTypeBlob assemGen tyBlob
            | None -> noImpl()
        | _ -> noImpl()

    static member LLVMVarTypeOfMaybeByRefType (assemGen : AssemGen) (mayByRefTy : FAP.MaybeByRefType) : LGC.TypeRef =
        let noImpl () = failwithf "LLVMVarTypeOfMaybeByRefType: no impl for %A type yet" mayByRefTy
        TypeUtil.LLVMVarTypeOfTypeBlob assemGen mayByRefTy.ty

    static member LLVMVarTypeOfLocalVar (assemGen : AssemGen) (locVar : FAP.LocalVarSig) : LGC.TypeRef =
        let noImpl () = failwithf "LLVMVarTypeOfLocalVar: no impl for %A type yet" locVar

        match locVar with
        | FAP.LocalVarSig.TypedByRef -> noImpl()
        | FAP.LocalVarSig.SpecifiedType specdLocVar ->
            if specdLocVar.pinned || not (Array.isEmpty specdLocVar.custMods) then
                noImpl()
            TypeUtil.LLVMVarTypeOfMaybeByRefType assemGen specdLocVar.mayByRefType

    static member LLVMVarTypeOfParam (assemGen : AssemGen) (param : FAP.Param) : LGC.TypeRef =
        let noImpl () = failwithf "LLVMVarTypeOfParam: no impl for %A type yet" param

        if not param.customMods.IsEmpty then
            noImpl()
        match param.pType with
        | FAP.ParamType.TypedByRef -> noImpl()
        | FAP.ParamType.MayByRefTy mayByRefTy ->
            TypeUtil.LLVMVarTypeOfMaybeByRefType assemGen mayByRefTy

    static member LLVMVarTypeOfRetType (assemGen : AssemGen) (retTy : FAP.RetType) : LGC.TypeRef =
        let noImpl() = failwithf "no impl for return type %A yet" retTy

        match retTy with
        | {FAP.RetType.customMods = []; FAP.RetType.rType = rType} ->
            match rType with
            | FAP.RetTypeKind.MayByRefTy {FAP.MaybeByRefType.isByRef = false; ty = ty} ->
                TypeUtil.LLVMVarTypeOfTypeBlob assemGen ty
            | FAP.RetTypeKind.Void ->
                voidTy
            | _ ->
                noImpl()
        | _ ->
            noImpl()

    static member LLVMVarTypeOfFieldDef (assemGen : AssemGen) (fieldDef : FAP.FieldDef) : LGC.TypeRef =
        if fieldDef.ConstantValue.IsSome then
            failwith "field constants not yet supported"
        if fieldDef.Data.IsSome then
            failwith "field data not yet supported"
        if fieldDef.HasDefault then
            failwith "field default not yet supported"
        if fieldDef.HasFieldMarshal then
            failwith "field marshal not yet supported"
        if fieldDef.Offset.IsSome then
            failwith "field offset not yet supported"

        let fieldSig = fieldDef.Signature
        if not fieldSig.customMods.IsEmpty then
            failwith "field custom mods not yet supported"
        TypeUtil.LLVMVarTypeOfTypeBlob assemGen fieldSig.fType

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
/// to detect when this truncation results in a value that doesn't correctly represent
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

// TODO we need a way to incapsulate interface info here!!!! Interfaces will return None type blobs
and StackItem private (bldr:LGC.BuilderRef, valueRef:LGC.ValueRef, stackType:FAP.StackType, typeBlobOpt:option<TyBlob>) =
    interface FAP.StackTyped with member x.StackType = stackType

    member x.ValueRef = valueRef
    member x.TypeBlobOpt = typeBlobOpt

    static member FromStackType
            (bldr : LGC.BuilderRef)
            (valueRef : LGC.ValueRef)
            (stackType : FAP.StackType)
            : StackItem =
        new StackItem(bldr, valueRef, stackType, None)

    static member FromTypeBlob
            (bldr : LGC.BuilderRef)
            (valueRef : LGC.ValueRef)
            (tyBlob : TyBlob)
            : StackItem =
        let valueRef =
            match tyBlob with
            | TyBlob.Boolean | TyBlob.Char | TyBlob.U1 | TyBlob.U2 ->
                LGC.buildZExt bldr valueRef int32Ty "zExtInt"
            | TyBlob.I1 | TyBlob.I2 ->
                LGC.buildSExt bldr valueRef int32Ty "sExtInt"
            | _ ->
                valueRef
        new StackItem(bldr, valueRef, tyBlob.AsIntermediateType(), Some tyBlob)

    static member FromType
            (bldr : LGC.BuilderRef)
            (valueRef : LGC.ValueRef)
            (ty : FAP.TypeDefRefOrSpec)
            : StackItem =
        let noImpl() = failwithf "StackItem.FromType: no implementation yet for %A" ty
        match ty.AsTypeBlob( (*false*) ) with
        | None -> noImpl()
        | Some tyBlob -> StackItem.FromTypeBlob bldr valueRef tyBlob

    static member FromParameter
            (bldr : LGC.BuilderRef)
            (value : LGC.ValueRef)
            (param : FAP.Parameter)
            : StackItem =
        let noImpl() = failwithf "StackItem.FromParameter: no implementation yet for %A" param
        match param.Type.pType with
        | FAP.ParamType.TypedByRef -> noImpl()
        | FAP.ParamType.MayByRefTy mayByRefTy ->
            if mayByRefTy.isByRef then
                noImpl()
            StackItem.FromTypeBlob bldr value mayByRefTy.ty

    static member FromLocal
            (bldr : LGC.BuilderRef)
            (value : LGC.ValueRef)
            (local : FAP.LocalVarSig)
            : StackItem =

        let noImpl() = failwithf "StackItem.FromLocal: no implementation for: %A" local
        match local with
        | FAP.LocalVarSig.TypedByRef -> noImpl()
        | FAP.LocalVarSig.SpecifiedType specLocalVar ->
            if specLocalVar.pinned || specLocalVar.mayByRefType.isByRef || specLocalVar.custMods.Length <> 0 then
                noImpl()
            StackItem.FromTypeBlob bldr value specLocalVar.mayByRefType.ty

    static member FromReturnType
            (bldr : LGC.BuilderRef)
            (valueRef : LGC.ValueRef)
            (retTy : FAP.RetType)
            : StackItem =

        let noImpl() = failwithf "StackItem.FromReturnType: no implementation for: %A" retTy
        if not retTy.customMods.IsEmpty then
            noImpl()
        match retTy.rType with
        | FAP.RetTypeKind.Void -> failwith "It is invalid to build a StackItem from a void return value"
        | FAP.RetTypeKind.TypedByRef -> noImpl()
        | FAP.RetTypeKind.MayByRefTy mayByRefTy ->
            if mayByRefTy.isByRef then
                noImpl()
            StackItem.FromTypeBlob bldr valueRef mayByRefTy.ty

    static member FromField
            (bldr : LGC.BuilderRef)
            (valueRef : LGC.ValueRef)
            (field : FAP.FieldDef)
            : StackItem =

        let fSig = field.Signature
        let noImpl() = failwithf "StackItem.FromField: no implementation for: %A" fSig
        if not fSig.customMods.IsEmpty then
            noImpl()
        StackItem.FromTypeBlob bldr valueRef fSig.fType

    member x.AsInt (asSigned:bool) (asSize:PrimSizeBytes) : LGC.ValueRef =
        let size = sizeOfStackType stackType
        match stackType with
        | FAP.Int_ST ->
            if asSize = size then
                valueRef
            elif asSize < size then
                LGC.buildTrunc bldr valueRef (llvmIntTypeSized asSize) "truncInt"
            else
                let extFun = if asSigned then LGC.buildSExt else LGC.buildZExt
                extFun bldr valueRef (llvmIntTypeSized asSize) "extendedInt"
        | FAP.Float_ST ->
            LGC.buildFPToSI bldr valueRef (llvmIntTypeSized asSize) "truncatedFP"
        | FAP.ObjectRef_ST ->
            LGC.buildPtrToInt bldr valueRef (llvmIntTypeSized asSize) "ptrAsInt"
        | _ ->
            failwithf "TODO implement int conversion for %A" stackType

    member x.AsNativeInt (asSigned:bool) = x.AsInt asSigned nativeIntSize

    member x.AsFloat (fromSigned:bool) (asDouble:bool) : LGC.ValueRef =
        let asTy = if asDouble then doubleTy else floatTy
        match stackType with
        | FAP.Float32_ST ->
            if asDouble
            then LGC.buildFPExt bldr valueRef asTy "extendedFloat"
            else valueRef
        | FAP.Float64_ST ->
            if asDouble
            then valueRef
            else LGC.buildFPTrunc bldr valueRef asTy "truncFloat"
        | FAP.Int_ST ->
            // TODO do we actually need "fromSigned"?
            if fromSigned
            then LGC.buildSIToFP bldr valueRef asTy "convVal"
            else LGC.buildUIToFP bldr valueRef asTy "convVal"
        | _ -> failwithf "implicit cast from %A to float32 is not allowed" stackType

    member x.AsStackType (asTy:StackType) : LGC.ValueRef =
        let cantConv() = failwithf "StackItem.AsStackType: cannot convert %A to %A" stackType asTy
        match asTy with
        | StackType.Int32_ST -> x.AsInt false PrimSizeBytes.Four
        | StackType.Int64_ST -> x.AsInt false PrimSizeBytes.Eight
        | StackType.NativeInt_ST -> x.AsNativeInt false
        | StackType.Float32_ST -> x.AsFloat true false
        | StackType.Float64_ST -> x.AsFloat true true
        | StackType.ObjectRef_ST -> cantConv()
        | StackType.ManagedPointer_ST -> cantConv()

    member x.AsType (assemGen:AssemGen) (asTy:FAP.TypeDefRefOrSpec) : LGC.ValueRef =
        let noImpl() =
            failwithf "StackItem.AsType: cannot convert %A to %s" typeBlobOpt (asTy.CilId(false, assemGen.Assembly))
        match typeBlobOpt with
        | None -> valueRef
        | Some fromTyBlob ->
            let asTy =
                match asTy with
                | :? FAP.TypeDefOrRef as asTy -> asTy.Resolve()
                | _ -> noImpl()

            match asTy.AsTypeBlob( (*false*) ) with
            | None -> noImpl()
            | Some asTy -> x.AsTypeBlob assemGen asTy

    member x.AsTypeBlob (assemGen:AssemGen) (tyBlob:TyBlob) : LGC.ValueRef =
        // TODO we should have more checks here. Especially where we return the naked value ref.
        let noImpl() = failwithf "StackItem.AsTypeBlob: no implementation for: %A -> %A" typeBlobOpt tyBlob

        let asClassOrValuetype (asTy:FAP.TypeDefRefOrSpec) =
            match typeBlobOpt with
            | None -> valueRef
            | Some fromTyBlob ->
                let asTy =
                    match asTy with
                    | :? FAP.TypeDefOrRef as asTy -> asTy.Resolve()
                    | _ -> noImpl()
                let bitCastAsPtrToAsTy() =
                    let ptrTy = LGC.pointerType (assemGen.GetTypeRep(asTy).InstanceVarsType) 0u
                    LGC.buildBitCast bldr valueRef ptrTy ""
                let handleBasicCase (fromTy:FAP.TypeDefRefOrSpec) =
                    match fromTy with
                    | :? FAP.TypeDefOrRef as fromTy ->
                        let fromTy = fromTy.Resolve()
                        if fromTy = asTy then
                            valueRef
                        else
                            bitCastAsPtrToAsTy()
                    | _ ->
                        noImpl()
                match fromTyBlob with
                | TyBlob.Class fromTy | TyBlob.ValueType fromTy ->
                    handleBasicCase fromTy
                | TyBlob.String ->
                    handleBasicCase assemGen.Mscorlib.StringTypeDef
                | TyBlob.SzArray (custMods, elemTy) ->
                    if not custMods.IsEmpty then
                        noImpl()
                    if asTy = assemGen.Mscorlib.SysArrayTypeDef then
                        bitCastAsPtrToAsTy()
                    else
                        noImpl()
                | TyBlob.Ptr (custMods, pointeeTyOpt) ->
                    if not custMods.IsEmpty then
                        noImpl()
                    match pointeeTyOpt with
                    | None -> noImpl()
                    | Some pointeeTy ->
                        bitCastAsPtrToAsTy()
                | _ ->
                    noImpl()

        match tyBlob with
        | TyBlob.Boolean | TyBlob.U1 -> x.AsInt false PrimSizeBytes.One
        | TyBlob.Char -> x.AsInt false PrimSizeBytes.Two
        | TyBlob.U2 -> x.AsInt false PrimSizeBytes.Two
        | TyBlob.I1 -> x.AsInt true PrimSizeBytes.One
        | TyBlob.I2 -> x.AsInt true PrimSizeBytes.Two
        | TyBlob.I4 -> x.AsInt true PrimSizeBytes.Four
        | TyBlob.U4 -> x.AsInt false PrimSizeBytes.Four
        | TyBlob.I8 -> x.AsInt true PrimSizeBytes.Eight
        | TyBlob.U8 -> x.AsInt false PrimSizeBytes.Eight
        | TyBlob.R4 -> x.AsFloat true false
        | TyBlob.R8 -> x.AsFloat true true
        | TyBlob.String -> asClassOrValuetype assemGen.Mscorlib.StringTypeDef
        | TyBlob.Ptr _ -> valueRef
        | TyBlob.ValueType ty | TyBlob.Class ty -> asClassOrValuetype ty
        | TyBlob.Object -> asClassOrValuetype assemGen.Mscorlib.ObjectTypeDef
        //| TyBlob.Class ty -> asClassOrValuetype ty
        | TyBlob.Var _ -> noImpl ()
        | TyBlob.Array _ -> noImpl()
        | TyBlob.GenericInst _ -> noImpl()
        | TyBlob.I -> x.AsNativeInt true
        | TyBlob.U -> x.AsNativeInt false
        | TyBlob.FnPtr _ -> noImpl()
        | TyBlob.MVar _ -> noImpl()
        | TyBlob.SzArray (custMods, elemTyBlob) ->
            if not custMods.IsEmpty then
                noImpl()
            valueRef

    member x.AsReturnType (assemGen:AssemGen) (retTy:FAP.RetType) : LGC.ValueRef =
        let noImpl() = failwithf "StackItem.AsReturnType: no implementation for: %A" retTy
        if not retTy.customMods.IsEmpty then
            noImpl()

        match retTy.rType with
        | FAP.RetTypeKind.TypedByRef -> noImpl()
        | FAP.RetTypeKind.Void -> noImpl()
        | FAP.RetTypeKind.MayByRefTy mayByRefTy ->
            if mayByRefTy.isByRef then
                noImpl()
            x.AsTypeBlob assemGen mayByRefTy.ty

    member x.AsParam (assemGen:AssemGen) (param:FAP.Param) : LGC.ValueRef =
        let noImpl() = failwithf "StackItem.AsParam: no implementation for: %A" param
        if not param.customMods.IsEmpty then
            noImpl()

        match param.pType with
        | FAP.ParamType.TypedByRef -> noImpl()
        | FAP.ParamType.MayByRefTy mayByRefTy ->
            if mayByRefTy.isByRef then
                noImpl()
            x.AsTypeBlob assemGen mayByRefTy.ty

    member x.AsLocal (assemGen:AssemGen) (local:FAP.LocalVarSig) : LGC.ValueRef =
        let noImpl() = failwithf "StackItem.AsLocal: no implementation for: %A" local
        match local with
        | FAP.LocalVarSig.TypedByRef -> noImpl()
        | FAP.LocalVarSig.SpecifiedType specLocalVar ->
            if specLocalVar.pinned || specLocalVar.mayByRefType.isByRef || specLocalVar.custMods.Length <> 0 then
                noImpl()
            x.AsTypeBlob assemGen specLocalVar.mayByRefType.ty

    member x.AsField (assemGen:AssemGen) (field:FAP.FieldDef) : LGC.ValueRef =
        let fSig = field.Signature
        let noImpl() = failwithf "StackItem.AsField: no implementation for: %A" fSig
        if not fSig.customMods.IsEmpty then
            noImpl()

        x.AsTypeBlob assemGen fSig.fType

and MethodRep(typeRep:TypeRep, methDef:FAP.MethodDef) =
    let assemGen = typeRep.AssemGen
    let moduleRef = assemGen.ModuleRef

    // corresponds to instruction stelem
    let storeArrayElem (bldr:LGC.BuilderRef) (value:LGC.ValueRef) (index:LGC.ValueRef) (arrObj:LGC.ValueRef) =
        let arrPtrAddr = LGC.buildStructGEP bldr arrObj 1u "arrPtrAddr"
        let arrPtr = LGC.buildLoad bldr arrPtrAddr "arrPtr"
        let elemAddr = LC.buildGEP bldr arrPtr [|index|] "elemAddr"
        LGC.buildStore bldr value elemAddr |> ignore

    let makeNewObj (bldr:LGC.BuilderRef) (ctor:FAP.Method) (args:StackItem list) =
        // TODO implement GC along with object/class initialization code
        // FIXME naming is all screwed up! fix it
        let ctor = ctor.Resolve()
        if not ctor.IsCtor then
            failwith "expected a .ctor here"
        else
            let decTy = ctor.DeclaringType
            let tyRep = assemGen.GetTypeRep(decTy)
            let llvmTy = tyRep.InstanceVarsType
            let ctorRef = tyRep.GetMethRep(ctor).ValueRef
            let newObj = LGC.buildMalloc bldr llvmTy ("new" + ctor.DeclaringType.Name)
            
            let allParams = ctor.AllParameters
            let stackItemToArg (i:int) (item:StackItem) =
                item.AsParam assemGen allParams.[i + 1].Type
            let args = newObj :: List.mapi stackItemToArg args

            (*
            printfn "building ctor call for <<%s>>" (ctor.CilId assemGen.Assembly)
            printfn "args:"
            for i = 0 to args.Length - 1 do
                printfn "  %s" (LLVM.Extra.typeToString moduleRef (LGC.typeOf args.[i]))
            printfn "ctorRef type = %s" (LLVM.Extra.typeToString moduleRef (LGC.typeOf ctorRef))
            *)

            LC.buildCall bldr ctorRef (Array.ofList args) "" |> ignore
            
            // TODO is this type valid? it was cut-and-paste from my old code
            let ty : TyBlob =
                match decTy.AsTypeBlob( (*false*) ) with
                | None -> failwith "cannot build a constructor for an interface!"
                | Some ty -> ty

            StackItem.FromTypeBlob bldr newObj ty

    let declareMethod() : LGC.ValueRef =

        // TODO there are many more method properties that we can and should be looking at
        let nameFunParam (fn : LGC.ValueRef) (i : int) (p : FAP.Parameter) : unit =
            let llvmParam = LGC.getParam fn (uint32 i)
            LGC.setValueName llvmParam p.Name

        match methDef.MethodBody with
        | Some methBody ->
            let paramTys = [|for p in methDef.AllParameters -> TypeUtil.LLVMVarTypeOfParam assemGen p.Type|]
            let retTy = TypeUtil.LLVMVarTypeOfRetType assemGen methDef.ReturnType
            let funcTy = LC.functionType retTy paramTys
            let fnName =
                if methDef.IsStatic then
                    if methDef.Name = "main" then "_main" else methDef.Name
                else
                    methDef.FullName

            let fn = LGC.addFunction moduleRef fnName funcTy
            Array.iteri (nameFunParam fn) methDef.AllParameters
        
            fn
        | None ->
            match methDef.CodeType, methDef.PInvokeInfo with
            // TODO why is this IL and not native???
            | FAP.CodeType.IL, Some pInv ->
                // TODO for now assuming that we don't need to use "dlopen"
                if pInv.ModuleRef.Name <> "libc.dll" then
                    failwith "sorry! only works with libc for now. No dlopen etc."

                let paramTys = [|for p in methDef.AllParameters -> TypeUtil.LLVMVarTypeOfParam assemGen p.Type|]
                let retTy = TypeUtil.LLVMVarTypeOfRetType assemGen methDef.ReturnType
                let funcTy = LC.functionType retTy paramTys
                let fn = LGC.addFunction moduleRef pInv.ImportName funcTy
                LGC.setLinkage fn LGC.Linkage.ExternalLinkage

                Seq.iteri (nameFunParam fn) methDef.Parameters

                fn
            | ctPi ->
                if methDef.IsInternalCall then
                    // TODO implement internal call for real!
                    let paramTys = [|for p in methDef.AllParameters -> TypeUtil.LLVMVarTypeOfParam assemGen p.Type|]
                    let retTy = TypeUtil.LLVMVarTypeOfRetType assemGen methDef.ReturnType
                    let funcTy = LC.functionType retTy paramTys
                    let fn = LGC.addFunction moduleRef methDef.Name funcTy
                    //LGC.setLinkage fn LGC.Linkage.ExternalLinkage

                    Seq.iteri (nameFunParam fn) methDef.Parameters

                    fn
                else
                    failwithf "bad function with no body %A" methDef

    let rec genBlockInsts
            (bldr : LGC.BuilderRef)
            (args : LGC.ValueRef array)
            (locals : LGC.ValueRef array)
            (llvmBlocks : LGC.BasicBlockRef array)
            (blockIndex : int)
            (insts : Inst list)
            (stackVals : StackItem list)
            : unit =

        match insts with
        | [] -> ()
        | inst :: instTail ->
            printfn "Inst: %A" inst

            let poppedStack, stackTail = inst.PopTypes stackVals
            let pushTypes =
                match inst.TypesToPush methDef poppedStack with
                | Some pushTypes -> pushTypes
                | None -> []
            let pushType () =
                match pushTypes with
                | [tyToPush] -> tyToPush
                | tysToPush -> failwithf "expected exactly one type to push but got %A" tysToPush

            let goNext (stackVals : StackItem list) =
                genBlockInsts bldr args locals llvmBlocks blockIndex instTail stackVals
            let goNextStackItem (si : StackItem) =
                goNext (si :: stackTail)
            let goNextValRef (value : LGC.ValueRef) =
                goNextStackItem (StackItem.FromStackType bldr value (pushType()))

            let noImpl() = failwithf "instruction <<%A>> not implemented" inst
            let unexpPush() = failwithf "unexpected push types <<%A>> for instruction <<%A>>" pushType inst
            let unexpPop() = failwithf "unexpected pop types <<%A>> for instruction <<%A>>" poppedStack inst

            let brBool (nonZeroBB : int) (zeroBB : int) =
                match poppedStack with
                | [value] ->
                    // TODO would be more efficient to have custom test per size
                    let valToTest = value.AsInt false PrimSizeBytes.Eight
                    let zero = LC.constUInt64 0uL
                    let isZero = LGC.buildICmp bldr LGC.IntPredicate.IntEQ valToTest zero "isZero"
                    let nonZeroBlk = llvmBlocks.[nonZeroBB]
                    let zeroBlk = llvmBlocks.[zeroBB]
                    LGC.buildCondBr bldr isZero zeroBlk nonZeroBlk |> ignore
                | _ ->
                    failwithf "expected a single value to be popped from the stack for: %A" inst

            match inst with
            | Inst.Add ->
                // The add instruction adds value2 to value1 and pushes the result
                // on the stack. Overflow is not detected for integral operations
                // (but see add.ovf); floating-point overflow returns +inf or -inf.
                match poppedStack with
                | [value2; value1] ->
                    // first convert the two add values to the type that we're supposed
                    // to push on the stack
                    let pushTy = pushType()
                    let v1 = value1.AsStackType(pushTy)
                    let v2 = value2.AsStackType(pushTy)
                    let addResult =
                        match pushTy with
                        | FAP.Float_ST -> LGC.buildFAdd bldr v1 v2 "tmpFAdd"
                        | FAP.Int_ST -> LGC.buildAdd bldr v1 v2 "tmpAdd"
                        | _ -> unexpPush()
                    goNextValRef addResult
                | _ -> unexpPop()

            | Inst.And -> noImpl()
            | Inst.Beq trueBB | Inst.Bge trueBB | Inst.Bgt trueBB
            | Inst.Ble trueBB | Inst.Blt trueBB | Inst.BneUn trueBB
            | Inst.BgeUn trueBB | Inst.BgtUn trueBB | Inst.BleUn trueBB
            | Inst.BltUn trueBB ->
            
                if not instTail.IsEmpty then
                    failwithf "the instruction stack should be empty after a branch: %A" instTail
            
                let isSigned() =
                    match inst with
                    | Inst.BneUn _ | Inst.BgeUn _ | Inst.BgtUn _
                    | Inst.BleUn _ | Inst.BltUn _ ->
                        false
                    | _ ->
                        true

                let brInt i1 i2 =
                    let brWith op =
                        let brTest = LGC.buildICmp bldr op i1 i2 "brTest"
                        let trueBlock = llvmBlocks.[trueBB]
                        let falseBlock = llvmBlocks.[blockIndex + 1]
                        LGC.buildCondBr bldr brTest trueBlock falseBlock |> ignore
                    match inst with
                    | Inst.Beq _    -> brWith LGC.IntPredicate.IntEQ
                    | Inst.Bge _    -> brWith LGC.IntPredicate.IntSGE
                    | Inst.BgeUn _  -> brWith LGC.IntPredicate.IntUGE
                    | Inst.Bgt _    -> brWith LGC.IntPredicate.IntSGT
                    | Inst.BgtUn _  -> brWith LGC.IntPredicate.IntUGT
                    | Inst.Ble _    -> brWith LGC.IntPredicate.IntSLE
                    | Inst.BleUn _  -> brWith LGC.IntPredicate.IntULE
                    | Inst.Blt _    -> brWith LGC.IntPredicate.IntSLT
                    | Inst.BltUn _  -> brWith LGC.IntPredicate.IntULT
                    | Inst.BneUn _  -> brWith LGC.IntPredicate.IntNE
                    | _             -> failwith "this error should be impossible!"

                match poppedStack with
                | [FAP.STyped FAP.NativeInt_ST as value2;
                  (FAP.STyped FAP.NativeInt_ST | FAP.STyped FAP.Int32_ST) as value1]
                | [(FAP.STyped FAP.NativeInt_ST | FAP.STyped FAP.Int32_ST) as value2;
                  FAP.STyped FAP.NativeInt_ST as value1] ->
                    let i1 = value1.AsNativeInt(isSigned())
                    let i2 = value2.AsNativeInt(isSigned())
                    brInt i1 i2
                | [FAP.STyped FAP.Int32_ST as value2; FAP.STyped FAP.Int32_ST as value1]
                | [FAP.STyped FAP.Int64_ST as value2; FAP.STyped FAP.Int64_ST as value1] ->
                    brInt value1.ValueRef value2.ValueRef
                | _ ->
                    failwithf "branching not yet implemented for types: %A" [for x in poppedStack -> (x :> FAP.StackTyped).StackType]

            | Inst.Br brIndex ->
                LGC.buildBr bldr llvmBlocks.[brIndex] |> ignore
            | Inst.Break -> noImpl()
            | Inst.Brfalse brIndex -> brBool (blockIndex + 1) brIndex
            | Inst.Brtrue brIndex -> brBool brIndex (blockIndex + 1)
            | Inst.Call call ->
                // look up the corresponding LLVM function
                let methDef = call.Method.Resolve()
                let funRef = assemGen.GetTypeRep(methDef.DeclaringType).GetMethRep(methDef).ValueRef

                let allParams = methDef.AllParameters
                let stackItemToArg (i:int) (item:StackItem) =
                    item.AsParam assemGen allParams.[i].Type
                let argStack = List.rev poppedStack
                let args = List.mapi stackItemToArg argStack
                let resultName = if pushTypes.IsEmpty then "" else "callResult"

                let callResult = LC.buildCall bldr funRef (Array.ofList args) resultName

                if call.Tail then LGC.setTailCall callResult true
                if pushTypes.IsEmpty then
                    goNext stackTail
                else
                    goNextStackItem(StackItem.FromReturnType bldr callResult methDef.ReturnType)

            | Inst.Calli call -> noImpl()
            | Inst.Callvirt virtCall -> noImpl()
            | Inst.ConvI1 -> noImpl()
            | Inst.ConvI2 -> noImpl()
            | Inst.ConvI4 ->
                match poppedStack with
                | [value] -> goNextValRef (value.AsInt true PrimSizeBytes.Four)
                | _ -> unexpPop()

            | Inst.ConvI8 -> noImpl()
            | Inst.ConvR4 -> noImpl()
            | Inst.ConvR8 ->
                match poppedStack with
                | [value] -> goNextValRef (value.AsFloat true true)
                | _ -> noImpl()

            | Inst.ConvU4 -> noImpl()
            | Inst.ConvU8 -> noImpl()
            | Inst.Cpobj ty -> noImpl()
            | Inst.Div ->
                // TODO need to add a proper exception for div by zero I think
                match poppedStack with
                | [value2; value1] ->
                    let pushTy = pushType()
                    let v1 = value1.AsStackType(pushTy)
                    let v2 = value2.AsStackType(pushTy)
                    let divResult =
                        match pushTy with
                        | FAP.Float_ST -> LGC.buildFDiv bldr v1 v2 "tmpFDiv"
                        | FAP.Int_ST -> LGC.buildSDiv bldr v1 v2 "tmpDiv"
                        | _ -> unexpPush()
                    goNextValRef divResult
                | _ -> unexpPop()

            | Inst.DivUn -> noImpl()
            | Inst.Dup ->
                // TODO confirm this is OK
                match poppedStack with
                | [value] -> goNext (value :: value :: stackTail)
                | _ -> unexpPop()

            | Inst.Jmp metaTok -> noImpl()
            | Inst.Ldarg argIndex ->
                let paramDef = methDef.AllParameters.[int argIndex]
                let name = "tmp_" + paramDef.Name
                let value = LGC.buildLoad bldr args.[int argIndex] name
                goNextStackItem (StackItem.FromParameter bldr value paramDef)

            | Inst.Ldarga argIndex ->
                // TODO I think the logic for ldarga needs to act just like ldarg for
                // any objects or complex value types...

                let argIndex = int argIndex
                let paramDef = methDef.AllParameters.[argIndex]
                if not paramDef.CustomMods.IsEmpty then
                    noImpl()
                match paramDef.Type.pType with
                | FAP.ParamType.TypedByRef -> noImpl()
                | FAP.ParamType.MayByRefTy mayByRefTy ->
                    if mayByRefTy.isByRef then
                        noImpl()
                    let ptrTy = TyBlob.PtrTo mayByRefTy.ty
                    let value =
                        if mayByRefTy.ty.IsObjOrVal then
                            LGC.buildLoad bldr args.[int argIndex] ("tmpptr_" + paramDef.Name)
                        else
                            args.[argIndex]
                    goNextStackItem (StackItem.FromTypeBlob bldr value ptrTy)

            | Inst.LdcI4 i ->
                goNextStackItem (StackItem.FromTypeBlob bldr (LC.constInt32 i) TyBlob.I4)

            | Inst.LdcI8 i -> noImpl()
            | Inst.LdcR4 r -> noImpl()
            | Inst.LdcR8 r ->
                goNextStackItem (StackItem.FromTypeBlob bldr (LC.constDouble r) TyBlob.R8)
            | Inst.LdindI1 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindU1 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindI2 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindU2 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindI4 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindU4 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindI8 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindI (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindR4 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindR8 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.LdindRef (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.Ldloc locIndex ->
                let locIndex = int locIndex
                let local = methDef.Locals.[locIndex]
                let loadResult = LGC.buildLoad bldr locals.[locIndex] "tmp"

                goNextStackItem (StackItem.FromLocal bldr loadResult local)

            | Inst.Ldloca varIndex -> noImpl()
            | Inst.Ldnull -> noImpl()
            | Inst.Ldobj (unalignedOpt, volatilePrefix, ty) -> noImpl()
            | Inst.Ldstr str ->
                // TODO the following is not done here
                //
                // Partition III 4.16:
                //
                // By default, the CLI guarantees that the result of two
                // ldstr instructions referring to two metadata tokens that
                // have the same sequence of characters, return precisely
                // the same string object (a process known as "string interning").
                // This behavior can be controlled using the
                // System.Runtime.CompilerServices. CompilationRelaxationsAttribute
                // and the System.Runtime.CompilerServices.
                // CompilationRelaxations.NoStringInterning (see Partition IV).
                match poppedStack with
                | [] ->
                    // allocate the string array
                    let sizeInt = LGC.constInt nativeIntTy (uint64 str.Length) false
                    let arrTy, arrVal = CodeGenUtil.MakeNewArray assemGen bldr assemGen.Mscorlib.CharTypeDef sizeInt

                    // fill in the string array
                    // TODO this is super-duper inefficient
                    for i = 0 to str.Length - 1 do
                        let iConst = LGC.constInt nativeIntTy (uint64 i) false
                        let charConst = LC.constUInt16 (uint16 str.[i])
                        storeArrayElem bldr charConst iConst arrVal

                    // call the string constructor
                    let ctorMatch (md:FAP.MethodDef) : bool =
                        if md.IsCtor then
                            match md.Parameters with
                            | [|singleParam|] ->
                                match singleParam.Type.pType with
                                | FAP.ParamType.MayByRefTy mayByRef ->
                                    //mayByRef.ty = TyBlob.I
                                    match mayByRef.ty with
                                    | TyBlob.SzArray ([], TyBlob.Char) ->
                                        true
                                    | _ ->
                                        false
                                | FAP.ParamType.TypedByRef ->
                                    false
                            | _ ->
                                false
                        else
                            false
                    let strTyDef = assemGen.Mscorlib.StringTypeDef
                    let ctor =
                        match Array.tryFind ctorMatch strTyDef.Methods with
                        | None -> failwith "failed to find suitable String constructor"
                        | Some ctor -> ctor
                    let strStackItem = makeNewObj bldr ctor [StackItem.FromTypeBlob bldr arrVal TyBlob.String]

                    goNextStackItem strStackItem

                | _ ->
                    noImpl()

            | Inst.Mul ->
                // The mul instruction multiplies value1 by value2 and pushes
                // the result on the stack. Integral operations silently
                // truncate the upper bits on overflow (see mul.ovf).
                // TODO: For floating-point types, 0 x infinity = NaN.
                match poppedStack with
                | [value2; value1] ->
                    let pushTy = pushType()
                    let v1 = value1.AsStackType(pushTy)
                    let v2 = value2.AsStackType(pushTy)
                    let mulResult =
                        match pushTy with
                        | FAP.Float_ST -> LGC.buildFMul bldr v1 v2 "tmpFMul"
                        | FAP.Int_ST -> LGC.buildMul bldr v1 v2 "tmpMul"
                        | _ -> unexpPush()
                    goNextValRef mulResult
                | _ -> unexpPop()

            | Inst.Neg -> noImpl()
            | Inst.Nop ->
                match poppedStack with
                | [] -> goNext stackVals
                | _ -> unexpPop()

            | Inst.Not -> noImpl()
            | Inst.Newobj ctor ->
                 makeNewObj bldr ctor (List.rev poppedStack)
                 |> goNextStackItem

            | Inst.Or -> noImpl()
            | Inst.Pop ->
                match poppedStack with
                | [_] -> goNext stackTail
                | _ -> unexpPop()

            | Inst.Rem -> noImpl()
            | Inst.RemUn -> noImpl()
            | Inst.Ret ->
                // The evaluation stack for the current method shall be empty
                // except for the value to be returned.
                if not stackTail.IsEmpty then
                    failwith "the value stack should be empty after a return"
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a return"

                match poppedStack with
                | [] ->
                    if not methDef.ReturnType.IsVoid then
                        failwith "expected a void return type"
                    LGC.buildRetVoid bldr |> ignore
                | [stackHead] ->
                    let retItem = stackHead.AsReturnType assemGen methDef.ReturnType
                    LGC.buildRet bldr retItem |> ignore
                | _ ->
                    unexpPop()

            | Inst.Shl -> noImpl()
            | Inst.Shr -> noImpl()
            | Inst.ShrUn -> noImpl()
            | Inst.Starg argIndex ->
                match poppedStack with
                | [stackHead] ->
                    let argIndex = int argIndex
                    let param = methDef.AllParameters.[argIndex].Type
                    let valRef = stackHead.AsParam assemGen param
                    LGC.buildStore bldr valRef args.[argIndex] |> ignore
                    goNext stackTail
                | _ -> unexpPop()

            | Inst.StindRef (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.StindI1 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.StindI2 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.StindI4 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.StindI8 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.StindR4 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.StindR8 (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.Stloc locIndex ->
                match poppedStack with
                | [stackHead] ->
                    let locIndex = int locIndex
                    let local = methDef.Locals.[locIndex]
                    let valRef = stackHead.AsLocal assemGen local

                    LGC.buildStore bldr valRef locals.[locIndex] |> ignore
                    goNext stackTail
                | _ -> unexpPop()

            | Inst.Sub ->
                // The sub instruction subtracts value2 from value1 and pushes the
                // result on the stack. Overflow is not detected for the integral
                // operations (see sub.ovf); for floating-point operands, sub
                // returns +inf on positive overflow inf on negative overflow, and
                // zero on floating-point underflow.
                match poppedStack with
                | [value2; value1] ->
                    // first convert the two add values to the type that we're supposed
                    // to push on the stack
                    let pushTy = pushType()
                    let v1 = value1.AsStackType(pushType())
                    let v2 = value2.AsStackType(pushType())
                    let subResult =
                        match pushType() with
                        | FAP.Float_ST -> LGC.buildFSub bldr v1 v2 "tmpFSub"
                        | FAP.Int_ST -> LGC.buildSub bldr v1 v2 "tmpSub"
                        | _ -> unexpPush()
                    goNextValRef subResult
                | _ -> unexpPop()

            | Inst.Switch blockIndexes ->
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a branch"
            
                match poppedStack with
                | [value] ->
                    let caseInts = [|for i in 0 .. blockIndexes.Length - 1 -> LC.constInt32 i|]
                    let caseBlocks = [|for b in blockIndexes -> llvmBlocks.[b]|]
                    let target = value.AsInt false PrimSizeBytes.Four
                    let fallthroughBlock = llvmBlocks.[blockIndex + 1]
                    LC.buildSwitchWithCases bldr target (Array.zip caseInts caseBlocks) fallthroughBlock
                | _ ->
                    unexpPop()

            | Inst.Xor -> noImpl()
            | Inst.Castclass ty -> noImpl()
            | Inst.Isinst ty -> noImpl()
            | Inst.ConvRUn -> noImpl()
            | Inst.Unbox ty -> noImpl()
            | Inst.Throw ->
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a throw"

                // TODO actually implement this for real
                let exitFun =
                    match LC.tryGetNamedFunction moduleRef "exit" with
                    | Some f -> f
                    | None ->
                        let exitFunTy = LC.functionType voidTy [|nativeIntTy|]
                        LGC.addFunction moduleRef "exit" exitFunTy
                let errCodeArg = LGC.constInt nativeIntTy 999uL false
                LC.buildCall bldr exitFun [|errCodeArg|] "" |> ignore

            | Inst.Ldfld (unalignedOpt, volatilePrefix, field) ->
                match poppedStack with
                | [obj] ->
                    // Partition III 4.10 says:
                    //
                    // The ldfld instruction pushes onto the stack the value of a field of obj.
                    // obj shall be an object (type O), a managed pointer (type &),
                    // an unmanaged pointer (type native int), or an instance of a value type.
                    // The use of an unmanaged pointer is not permitted in verifiable code.
                    // field is a metadata token (a fieldref or fielddef see Partition II)
                    // that shall refer to a field member. The return type is that associated
                    // with field. ldfld pops the object reference off the stack and pushes
                    // the value for the field in its place. The field can be either an instance
                    // field (in which case obj shall not be null) or a static field.
                    let field = field.Resolve()
                    let fieldName = field.Name
                    
                    if unalignedOpt.IsSome || volatilePrefix || field.IsStatic then
                        noImpl()

                    let fieldPtr =
                        match obj.TypeBlobOpt with
                        | Some (TyBlob.Ptr (custMods, Some pointeeTy)) when pointeeTy.IsPrimitive ->
                            if not custMods.IsEmpty then
                                noImpl()

                            if fieldName = "m_value" then
                                // TODO must assure that it's the right primitive
                                obj.ValueRef
                            else
                                noImpl()
                        | _ ->
                            let decTy = field.DeclaringType
                            let fieldIndex = Array.findIndex (fun f -> f = field) decTy.InstanceFields
                            let fieldIndex = fieldIndex + decTy.InheritedInstanceFields.Length

                            // OK now we need to load the field
                            let objPtrVal = obj.AsType assemGen decTy
                            let fieldPtr = LGC.buildStructGEP bldr objPtrVal (uint32 fieldIndex) (fieldName + "Ptr")

                            fieldPtr

                    let fieldValue = LGC.buildLoad bldr fieldPtr (fieldName + "Value")
                    let fieldStackItem = StackItem.FromField bldr fieldValue field
                    goNextStackItem fieldStackItem
                | _ ->
                    unexpPop()

            | Inst.Ldflda (unalignedOpt, volatilePrefix, field) -> noImpl()
            | Inst.Stfld (unalignedOpt, volatilePrefix, field) ->
                match poppedStack with
                | [value; selfPtr] ->
                    if unalignedOpt.IsSome || volatilePrefix then
                        noImpl()

                    let field = field.Resolve()

                    let decTy = field.DeclaringType
                    let fieldIndex = Array.findIndex (fun f -> f = field) decTy.InstanceFields
                    let fieldIndex = fieldIndex + decTy.InheritedInstanceFields.Length

                    // now we need to store the field
                    let fieldPtr = LGC.buildStructGEP bldr selfPtr.ValueRef (uint32 fieldIndex) (field.Name + "Ptr")
                    LGC.buildStore bldr (value.AsField assemGen field) fieldPtr |> ignore
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Inst.Ldsfld (volatilePrefix, field) ->
                match poppedStack with
                | [] ->
                    if volatilePrefix then
                        noImpl()

                    let field = field.Resolve()
                    let decTy = field.DeclaringType
                    let fieldIndex = Array.findIndex (fun f -> f = field) decTy.StaticFields

                    // OK now we need to load the field
                    let staticVarsRef = assemGen.GetTypeRep(decTy).StaticVarsGlobal
                    let fieldPtr = LGC.buildStructGEP bldr staticVarsRef (uint32 fieldIndex) (field.Name + "Ptr")
                    let fieldValue = LGC.buildLoad bldr fieldPtr (field.Name + "Value")
                    goNextStackItem(StackItem.FromField bldr fieldValue field)
                | _ ->
                    unexpPop()

            | Inst.Ldsflda (volatilePrefix, field) -> noImpl()
            | Inst.Stsfld (volatilePrefix, field) ->
                match poppedStack with
                | [value] ->
                    if volatilePrefix then
                        noImpl()

                    let field = field.Resolve()
                    let decTy = field.DeclaringType
                    let fieldIndex = Array.findIndex (fun f -> f = field) decTy.StaticFields

                    // now we need to store the field
                    let staticVarsRef = assemGen.GetTypeRep(decTy).StaticVarsGlobal
                    let fieldPtr = LGC.buildStructGEP bldr staticVarsRef (uint32 fieldIndex) (field.Name + "Ptr")
                    LGC.buildStore bldr (value.AsField assemGen field) fieldPtr |> ignore
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Inst.Stobj (unalignedOpt, volatilePrefix, ty) -> noImpl()
            | Inst.ConvOvfI1Un -> noImpl()
            | Inst.ConvOvfI2Un -> noImpl()
            | Inst.ConvOvfI4Un -> noImpl()
            | Inst.ConvOvfI8Un -> noImpl()
            | Inst.ConvOvfU1Un -> noImpl()
            | Inst.ConvOvfU2Un -> noImpl()
            | Inst.ConvOvfU4Un -> noImpl()
            | Inst.ConvOvfU8Un -> noImpl()
            | Inst.ConvOvfIUn -> noImpl()
            | Inst.ConvOvfUUn -> noImpl()
            | Inst.Box ty -> noImpl()
            | Inst.Newarr elemTypeRef ->
                match poppedStack with
                | [numElems] ->
                    let arrTy, newArrObj = CodeGenUtil.MakeNewArray assemGen bldr elemTypeRef (numElems.AsNativeInt false)
                    goNextStackItem (StackItem.FromTypeBlob bldr newArrObj arrTy)

                | _ ->
                    unexpPop()

            | Inst.Ldlen ->
                match poppedStack with
                | [arrObj] ->
                    let lenAddr = LGC.buildStructGEP bldr arrObj.ValueRef 0u "lenAddr"
                    goNextValRef (LGC.buildLoad bldr lenAddr "len")
                | _ ->
                    unexpPop()

            | Inst.Ldelema ty -> noImpl()
            | Inst.LdelemI1 -> noImpl()
            | Inst.LdelemU1 -> noImpl()
            | Inst.LdelemI2 -> noImpl()
            | Inst.LdelemU2 -> noImpl()
            | Inst.LdelemI4 -> noImpl()
            | Inst.LdelemU4 -> noImpl()
            | Inst.LdelemI8 -> noImpl()
            | Inst.LdelemI -> noImpl()
            | Inst.LdelemR4 -> noImpl()
            | Inst.LdelemR8 -> noImpl()
            | Inst.LdelemRef -> noImpl()
            | Inst.StelemI -> noImpl()
            | Inst.StelemI1 -> noImpl()
            | Inst.StelemI2 -> noImpl()
            | Inst.StelemI4 -> noImpl()
            | Inst.StelemI8 -> noImpl()
            | Inst.StelemR4 -> noImpl()
            | Inst.StelemR8 -> noImpl()
            | Inst.StelemRef -> noImpl()
            | Inst.Ldelem elemTy ->
                match poppedStack with
                | [index; arrObj] ->
                    let arrPtrAddr = LGC.buildStructGEP bldr arrObj.ValueRef 1u "arrPtrAddr"
                    let arrPtr = LGC.buildLoad bldr arrPtrAddr "arrPtr"
                    let elemAddr = LC.buildGEP bldr arrPtr [|index.AsNativeInt false|] "elemAddr"
                    let elem = LGC.buildLoad bldr elemAddr "elem"

                    goNextStackItem (StackItem.FromType bldr elem elemTy)
                | _ ->
                    unexpPop()

            | Inst.Stelem elemTyRef ->
                match poppedStack with
                | [value; index; arrObj] ->
                    storeArrayElem bldr (value.AsType assemGen elemTyRef) (index.AsNativeInt true) arrObj.ValueRef
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Inst.UnboxAny ty -> noImpl()
            | Inst.ConvOvfI1 -> noImpl()
            | Inst.ConvOvfU1 -> noImpl()
            | Inst.ConvOvfI2 -> noImpl()
            | Inst.ConvOvfU2 -> noImpl()
            | Inst.ConvOvfI4 -> noImpl()
            | Inst.ConvOvfU4 -> noImpl()
            | Inst.ConvOvfI8 -> noImpl()
            | Inst.ConvOvfU8 -> noImpl()
            | Inst.Refanyval metaTok -> noImpl()
            | Inst.Ckfinite -> noImpl()
            | Inst.Mkrefany metaTok -> noImpl()
            | Inst.Ldtoken metaTok ->
                (*
                The instruction sequence looks like:

	            IL_001c:  newarr [mscorlib]System.Char
	            IL_0021:  dup
	            IL_0022:  ldtoken field valuetype '<PrivateImplementationDetails$SimpleMain>'/T1374_16Bytes@ SimpleMain::field1375@
	            IL_0027:  call void class [mscorlib]System.Runtime.CompilerServices.RuntimeHelpers::InitializeArray(class [mscorlib]System.Array, valuetype [mscorlib]System.RuntimeFieldHandle)
	            IL_002c:  call void class SimpleMain::printString(char[])
	            IL_0031:  nop
	            IL_0032:  ret
                *)

                (*
                The function that I'm trying to figure out looks like:

		        [MethodImplAttribute(MethodImplOptions.InternalCall)]
		        static extern void InitializeArray (Array array, IntPtr fldHandle);

		        public static void InitializeArray (Array array, RuntimeFieldHandle fldHandle)
		        {
			        if ((array == null) || (fldHandle.Value == IntPtr.Zero))
				        throw new ArgumentNullException ();

			        InitializeArray (array, fldHandle.Value);
		        }
                *)

                // Description:
                // The ldtoken instruction pushes a RuntimeHandle for the specified metadata token.
                // The token shall be one of:
                // * A methoddef, methodref or methodspec: pushes a RuntimeMethodHandle
                // * A typedef, typeref, or typespec : pushes a RuntimeTypeHandle
                // * A fielddef or fieldref : pushes a RuntimeFieldHandle
                //
                // The value pushed on the stack can be used in calls to reflection methods in
                // the system class library
                match poppedStack with
                | [] ->
                    match metaTok with
                    | Some FPC.MetadataTableKind.FieldKind, _ ->
                        // resolve the RuntimeFieldHandle constructor
                        let ctorMatch (md:FAP.MethodDef) : bool =
                            if md.IsCtor then
                                match md.Parameters with
                                | [|singleParam|] ->
                                    match singleParam.Type.pType with
                                    | FAP.ParamType.MayByRefTy mayByRef ->
                                        mayByRef.ty = TyBlob.I
                                    | FAP.ParamType.TypedByRef ->
                                        false
                                | _ ->
                                    false
                            else
                                false
                        let ctor =
                            let runtimeField = assemGen.Mscorlib.RuntimeFieldHandleTypeDef
                            match Array.tryFind ctorMatch runtimeField.Methods with
                            | None -> failwith "failed to find RuntimeFieldHandle constructor"
                            | Some ctor -> ctor

                        // the field metadata pointer should be our constructors single argument
                        // (must be cast to a nativeint)
                        let fieldPtr =
                            let field = FAP.FieldDef.FromMetadataToken methDef.Assembly metaTok
                            let fieldRep = typeRep.GetFieldRep(field.Resolve())
                            let fieldMeta = fieldRep.MetadataGlobal
                            let fieldMeta = LGC.buildPointerCast bldr fieldMeta nativeIntTy ""
                            StackItem.FromStackType bldr fieldMeta StackType.NativeInt_ST

                        let newRuntimeFieldHandle = makeNewObj bldr ctor [fieldPtr]

                        goNextStackItem newRuntimeFieldHandle
                    | _ ->
                        noImpl()
                | _ ->
                    unexpPop()
            | Inst.ConvU2 -> noImpl()
            | Inst.ConvU1 -> noImpl()
            | Inst.ConvI -> noImpl()
            | Inst.ConvOvfI -> noImpl()
            | Inst.ConvOvfU -> noImpl()
            | Inst.AddOvf -> noImpl()
            | Inst.AddOvfUn -> noImpl()
            | Inst.MulOvf -> noImpl()
            | Inst.MulOvfUn -> noImpl()
            | Inst.SubOvf -> noImpl()
            | Inst.SubOvfUn -> noImpl()
            | Inst.Endfinally -> noImpl()
            | Inst.Leave tgtBlockIndex -> noImpl()
            | Inst.StindI (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.ConvU -> noImpl()
            | Inst.Arglist -> noImpl()
            | Inst.Ceq ->
                let ceqInt i1 i2 =
                    let cmpResult = LGC.buildICmp bldr LGC.IntPredicate.IntEQ i1 i2 "cmpResult"
                    let cmpResult = LGC.buildZExt bldr cmpResult int32Ty "extCmpResult"
                    let nextStackItem = StackItem.FromTypeBlob bldr cmpResult TyBlob.I4
                    goNextStackItem nextStackItem

                match poppedStack with
                | [FAP.STyped FAP.NativeInt_ST as value2;
                  (FAP.STyped FAP.NativeInt_ST | FAP.STyped FAP.Int32_ST) as value1]
                | [(FAP.STyped FAP.NativeInt_ST | FAP.STyped FAP.Int32_ST) as value2;
                  FAP.STyped FAP.NativeInt_ST as value1] ->
                    // TODO should this be sign extended or not??
                    let i1 = value1.AsNativeInt(false)
                    let i2 = value2.AsNativeInt(false)
                    ceqInt i1 i2
                | [FAP.STyped FAP.Int32_ST as value2; FAP.STyped FAP.Int32_ST as value1]
                | [FAP.STyped FAP.Int64_ST as value2; FAP.STyped FAP.Int64_ST as value1] ->
                    ceqInt value1.ValueRef value2.ValueRef
                | _ ->
                    failwithf "ceq not yet implemented for types: %A" [for x in poppedStack -> (x :> FAP.StackTyped).StackType]

            | Inst.Cgt -> noImpl()
            | Inst.CgtUn -> noImpl()
            | Inst.Clt -> noImpl()
            | Inst.CltUn -> noImpl()
            | Inst.Ldftn meth -> noImpl()
            | Inst.Ldvirtftn methTok -> noImpl()
            | Inst.Localloc -> noImpl()
            | Inst.Endfilter -> noImpl()
            | Inst.Initobj ty -> noImpl()
            | Inst.Cpblk volatilePrefix -> noImpl()
            | Inst.Initblk (unalignedOpt, volatilePrefix) -> noImpl()
            | Inst.Rethrow -> noImpl()
            | Inst.Sizeof ty -> noImpl()
            | Inst.Refanytype -> noImpl()

    let createEntryBlock (methodVal:LGC.ValueRef) =
        let entryBlock = LGC.appendBasicBlock methodVal "entry"
        use bldr = new LC.Builder(entryBlock)
        let args = [|
            for p in methDef.AllParameters ->
                let llvmTy = TypeUtil.LLVMVarTypeOfParam assemGen p.Type
                LGC.buildAlloca bldr llvmTy (p.Name + "_paramAlloca")
        |]
        for i = 0 to args.Length - 1 do
            LGC.buildStore bldr (LGC.getParam methodVal (uint32 i)) args.[i] |> ignore
        let locals =
            match methDef.MethodBody with
            | None -> [||]
            | Some methBody ->
                [|for localVarSig in methBody.locals ->
                    let llvmTy = TypeUtil.LLVMVarTypeOfLocalVar assemGen localVarSig
                    LGC.buildAlloca bldr llvmTy "localAlloca"|]

        entryBlock, args, locals

    let genStrCtorArrBody (methodVal:LGC.ValueRef) : unit =
        //printfn "$$$$$$$$$$$$ %A $$$$$$$$$$$$" methDef
        let entryBlock, args, _ = createEntryBlock methodVal
        use bldr = new LC.Builder(entryBlock)
        LGC.buildRetVoid bldr |> ignore

    let genInternalInitArray (methodVal:LGC.ValueRef) : unit =
        //printfn "############ %A ############" methDef
        let entryBlock, args, _ = createEntryBlock methodVal
        use bldr = new LC.Builder(entryBlock)

        (*
            static member MakeNewArray (assemGen:AssemGen) (bldr:LGC.BuilderRef) (elemTypeRef:FAP.TypeDefRefOrSpec) (numElemsValRef:LGC.ValueRef) =
                // TODO should this be changed to signed??? I think not
                //let numElemsValRef = numElems.AsNativeInt false

                // allocate the array to the heap
                // TODO it seems pretty lame to have this code here. need to think
                // about how this should really be structured
                let elemTy = TypeUtil.LLVMVarTypeOf assemGen elemTypeRef
                // TODO: make sure that numElems.Value is good here... will work for all native ints or int32's
                let elemTypeName = simpleTypeName elemTypeRef
                let newArr = LGC.buildArrayMalloc bldr elemTy numElemsValRef ("new" + elemTypeName + "Arr")

                // TODO I think we have to initialize the arrays

                let basicArrTy = LGC.pointerType elemTy 0u
                let arrObjTy = LC.structType [|nativeIntTy; basicArrTy|] false
                let newArrObj = LGC.buildMalloc bldr arrObjTy ("new" + elemTypeName + "ArrObj")

                // fill in the array object
                let lenAddr = LGC.buildStructGEP bldr newArrObj 0u "lenAddr"
                LGC.buildStore bldr numElemsValRef lenAddr |> ignore
                let arrPtrAddr = LGC.buildStructGEP bldr newArrObj 1u "arrPtrAddr"
                LGC.buildStore bldr newArr arrPtrAddr |> ignore

                let arrTy =
                    match elemTypeRef.AsTypeBlob() with
                    | None -> failwith "failed to convert array element type into a type"
                    | Some ty -> TyBlob.SzArrayOf ty

                //StackItem.FromTypeBlob bldr newArrObj arrTy
                (arrTy, newArrObj)
        *)

        (*
            // method line 11237
            .method private static hidebysig 
                   default void InitializeArray (class System.Array 'array', native int fldHandle)  cil managed internalcall 
            {
                // Method begins at RVA 0x0
            } // end of method RuntimeHelpers::InitializeArray
        *)

        (*
        and FieldRep(typeRep:TypeRep, fieldDef:FAP.FieldDef) =
            let modRef = typeRep.AssemGen.ModuleRef
            let structNamed name = LGC.structCreateNamed (LGC.getModuleContext modRef) name
            let data = match fieldDef.Data with None -> [||] | Some data -> data
            let metadataType = {
                new DefAndImpl<LGC.TypeRef>() with
                    member x.Define() = structNamed (fieldDef.FullName + "MetadataType")
                    member x.Implement metaTyRef =
                        LC.structSetBody metaTyRef [|nativeIntTy; LGC.arrayType int8Ty (uint32 data.Length)|] false
            }
            let metadataGlobal = lazy(
                let dataLenValRef = LGC.constInt nativeIntTy (uint64 data.Length) false
                let dataArrVal = LC.constArray int8Ty (Array.map LC.constUInt8 data)
                let metaConst = LC.constNamedStruct metadataType.Value [|dataLenValRef; dataArrVal|]

                addAndInitGlobal modRef metadataType.Value (fieldDef.FullName + "MetadataGlobal") metaConst
            )
            member x.MetadataGlobal : LGC.ValueRef = metadataGlobal.Value
        *)

        //let block = LGC.appendBasicBlock methodVal "block_0"

        LGC.buildRetVoid bldr |> ignore
 
    let maybeGenMethodBody (methodVal:LGC.ValueRef) : unit =

        match methDef.MethodBody with
        | None ->
            if methDef.IsInternalCall then
                let noImpl() =
                    failwithf "no implementation for internal call %s" (methDef.CilId assemGen.Assembly)
                
                let methParams = methDef.Parameters
                let decTy = methDef.DeclaringType
                if decTy = assemGen.Mscorlib.StringTypeDef then
                    match methDef.IsCtor, methDef.Parameters with
                    | true, [|SimplePTy (TyBlob.SzArray ([], TyBlob.Char))|] ->
                        genStrCtorArrBody methodVal
                    | _ ->
                        noImpl()
                elif decTy = assemGen.Mscorlib.RuntimeHelpersTypeDef then
                    let mscor = assemGen.Mscorlib
                    match methDef.IsStatic, methDef.Name, methDef.Parameters with
                    | true, "InitializeArray", [|SimplePTy (EqTy mscor mscor.SysArrayTypeDef true); SimplePTy TyBlob.I|] ->
                        genInternalInitArray methodVal
                    | _ ->
                        noImpl()
                else
                    noImpl()
            else
                ()
        | Some methBody ->
            printfn "== generating method body for: %s ==" (methDef.CilId assemGen.Assembly)
            
            // create the entry block
            let entryBlock, args, locals = createEntryBlock methodVal

            // declare all of the other blocks
            let blocks = methBody.blocks
            if blocks.Length = 0 then
                failwithf "empty method body: %s" methDef.Name
            let blockDecs = [|
                for i in 0 .. blocks.Length - 1 ->
                    printfn "block_%i length = %i" i blocks.[i].Length
                    LGC.appendBasicBlock methodVal (sprintf "block_%i" i)
            |]
            
            // build instructions for all of the blocks
            use bldr = new LC.Builder(entryBlock)
            LGC.buildBr bldr blockDecs.[0] |> ignore
            for i in 0 .. blocks.Length - 1 do
                use bldr = new LC.Builder(blockDecs.[i])
                let insts = [for inst, _ in blocks.[i] -> inst]
                genBlockInsts bldr args locals blockDecs i insts []

                // if the block doesn't end in a terminal we need to fall-through
                let currBlock = blocks.[i]
                let lastInst, _ = currBlock.[currBlock.Length - 1]
                if not lastInst.IsTerminal then
                    LGC.buildBr bldr blockDecs.[i + 1] |> ignore

    let valueRefDefAndImpl = {
        new DefAndImpl<LGC.ValueRef>(typeRep.WorkQueue) with
            member x.Define() = declareMethod()
            member x.Implement vr = maybeGenMethodBody vr
    }

    member x.ValueRef : LGC.ValueRef = valueRefDefAndImpl.Value

and FieldRep(typeRep:TypeRep, fieldDef:FAP.FieldDef) =
    let modRef = typeRep.AssemGen.ModuleRef
    let structNamed name = LGC.structCreateNamed (LGC.getModuleContext modRef) name
    let data = match fieldDef.Data with None -> [||] | Some data -> data
    let metadataType = {
        new DefAndImpl<LGC.TypeRef>() with
            member x.Define() = structNamed (fieldDef.FullName + "MetadataType")
            member x.Implement metaTyRef =
                LC.structSetBody metaTyRef [|nativeIntTy; LGC.arrayType int8Ty (uint32 data.Length)|] false
    }
    let metadataGlobal = lazy(
        let dataLenValRef = LGC.constInt nativeIntTy (uint64 data.Length) false
        let dataArrVal = LC.constArray int8Ty (Array.map LC.constUInt8 data)
        let metaConst = LC.constNamedStruct metadataType.Value [|dataLenValRef; dataArrVal|]

        addAndInitGlobal modRef metadataType.Value (fieldDef.FullName + "MetadataGlobal") metaConst
    )
    member x.MetadataGlobal : LGC.ValueRef = metadataGlobal.Value

and TypeRep(typeDef:FAP.TypeDef, assemGen:AssemGen) =
    let modRef = assemGen.ModuleRef
    let methRepMap = new Dict<FAP.MethodDef, MethodRep>()
    let fieldRepMap = new Dict<FAP.FieldDef, FieldRep>()
    let structNamed name = LGC.structCreateNamed (LGC.getModuleContext modRef) name
    let staticVarsType = {
        new DefAndImpl<LGC.TypeRef>() with
            member x.Define() = structNamed (typeDef.FullName + "Static")
            member x.Implement varsTy =
                let staticFields = [|
                    for f in typeDef.StaticFields ->
                        TypeUtil.LLVMVarTypeOfFieldDef assemGen f
                |]
                LC.structSetBody varsTy staticFields false
    }
    let staticVarsGlobal = lazy(
        addAndZeroInitGlobal modRef staticVarsType.Value (typeDef.FullName + "Global")
    )
    let instanceRef = {
        new DefAndImpl<LGC.TypeRef>() with
            member x.Define() = structNamed (typeDef.FullName + "Instance")
            member x.Implement vr =
                let instanceFields = [|
                    for f in typeDef.AllInstanceFields ->
                        TypeUtil.LLVMVarTypeOfFieldDef assemGen f
                |]
                LC.structSetBody vr instanceFields false
    }
    
    member x.WorkQueue : WorkQueue = assemGen.WorkQueue
    member x.AssemGen : AssemGen = assemGen
    member x.InstanceVarsType = instanceRef.Value
    member x.StaticVarsType = staticVarsType.Value
    member x.StaticVarsGlobal = staticVarsGlobal.Value
    member x.GetMethRep (md : FAP.MethodDef) : MethodRep =
        if methRepMap.ContainsKey md then
            methRepMap.[md]
        else
            let mr = new MethodRep(x, md)
            methRepMap.[md] <- mr
            mr
    member x.GetFieldRep (fd:FAP.FieldDef) : FieldRep =
        if fieldRepMap.ContainsKey fd then
            fieldRepMap.[fd]
        else
            let fr = new FieldRep(x, fd)
            fieldRepMap.[fd] <- fr
            fr

and AssemGen (modRef:LGC.ModuleRef, assembly:FAP.Assembly, workQueue:WorkQueue) =
    let typeRepMap = new Dict<FAP.TypeDef, TypeRep>()

    member x.WorkQueue = workQueue

    member x.Assembly : FAP.Assembly = assembly
    member x.Mscorlib : FAP.MscorlibAssembly = assembly.AssemblyResolution.Mscorlib
    member x.ModuleRef : LGC.ModuleRef = modRef
    member x.GetTypeRep (ty:FAP.TypeDefRefOrSpec) : TypeRep =
        match ty with
        | :? FAP.TypeDefOrRef as ty ->
            let ty = ty.Resolve()
            if typeRepMap.ContainsKey ty then
                typeRepMap.[ty]
            else
                let tr = new TypeRep(ty, x)
                typeRepMap.[ty] <- tr
                tr
        | _ ->
            failwithf "GetTypeRep: not yet implemented for %A" ty

let genMainFunction
        (assemGen : AssemGen)
        (entryPointDef : FAP.MethodDef)
        (llvmModuleRef : LGC.ModuleRef)
        : unit =
    let argcTy = int32Ty
    let argvTy = LGC.pointerType (LGC.pointerType int8Ty 0u) 0u
    let cMainFnTy = LC.functionType int32Ty [|argcTy; argvTy|]
    let cMainFn = LGC.addFunction llvmModuleRef "main" cMainFnTy
    LGC.setValueName (LGC.getParam cMainFn 0u) "argc"
    LGC.setValueName (LGC.getParam cMainFn 1u) "argv"

    use bldr = new LC.Builder(LGC.appendBasicBlock cMainFn "entry")
    let callResult =
        let resultName = if entryPointDef.ReturnType.IsVoid then "" else "result"
        match entryPointDef.AllParameters with
        | [||] ->
            let valRef = assemGen.GetTypeRep(entryPointDef.DeclaringType).GetMethRep(entryPointDef).ValueRef
            LC.buildCall bldr valRef [||] resultName
        | [|cmdLineArgs|] ->
            let badType () =
                failwithf "main function should take no arguments or String[] but instead found %A" cmdLineArgs
            if not cmdLineArgs.CustomMods.IsEmpty then
                failwith "no impl yet for custom mods in main function params"
            match cmdLineArgs.Type.pType with
            | FAP.ParamType.TypedByRef -> badType()
            | FAP.ParamType.MayByRefTy mayByRef ->
                if mayByRef.isByRef then
                    badType()
                match mayByRef.ty with
                | TyBlob.SzArray (custMods, elemTy) ->
                    if not custMods.IsEmpty then
                        failwith "no impl yet for custom mods in main function param elem type"
                    match elemTy with
                    | TyBlob.String ->
                        failwith "main taking string array not yet implemented"
                    | _ ->
                        badType()
                | _ ->
                    badType()
        | ps -> failwithf "expected main method to have zero or one argument but found %i arguments" ps.Length

    let retTy = entryPointDef.ReturnType
    let noRetTyImpl() =
        failwith "no implementation yet for main function return type: %A" retTy
    if not retTy.customMods.IsEmpty then
        noRetTyImpl()

    match retTy.rType with
    // TODO I think I should return a native in here not int32 right??
    | FAP.RetTypeKind.Void -> LGC.buildRet bldr (LC.constInt32 0) |> ignore
    | FAP.RetTypeKind.TypedByRef -> noRetTyImpl()
    | FAP.RetTypeKind.MayByRefTy mayByRef ->
        if mayByRef.isByRef then
            noRetTyImpl()
        match mayByRef.ty with
        | TyBlob.I4 -> LGC.buildRet bldr callResult |> ignore
        | _ -> noRetTyImpl()

let genTypeDefs (llvmModuleRef : LGC.ModuleRef) (assem : FAP.Assembly) : unit =
    let workQueue = new WorkQueue()
    let assemGen = new AssemGen(llvmModuleRef, assem, workQueue)

    // force evaluation of all module types
    let rec goTypeDef (td : FAP.TypeDef) =
        let classRep = assemGen.GetTypeRep(td)
        for m in td.Methods do
            classRep.GetMethRep(m).ValueRef |> ignore
        Seq.iter goTypeDef td.NestedTypes
    for m in assem.Modules do Seq.iter goTypeDef m.TypeDefs

    match assem.EntryPoint with
    | None -> ()
    | Some methDef -> genMainFunction assemGen methDef llvmModuleRef

    while workQueue.Count > 0 do
        let workItem = workQueue.Dequeue()
        workItem()
