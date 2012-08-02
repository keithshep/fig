module Fig.LLVMCodeGen

module FAP = Fig.AssemblyParser

module LC = LLVM.Core
module LGC = LLVM.Generated.Core

type Dict<'k, 'v> = System.Collections.Generic.Dictionary<'k, 'v>
type Inst = FAP.AbstInst
type TyBlob = FAP.TypeBlob
type StackType = FAP.StackType

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

type TypeUtil =
    static member LLVMVarTypeOfTypeBlob (assemGen : AssemGen) (tyBlob : TyBlob) : LGC.TypeRef =
        let noImpl() = failwithf "LLVMVarTypeOfTypeBlob: no impl for %A type yet" tyBlob

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
        | FAP.TypeBlob.Class ty ->
            LGC.pointerType (assemGen.GetTypeRep(ty).InstanceVarsType) 0u
        | FAP.TypeBlob.MVar _ -> noImpl()
        | FAP.TypeBlob.Object ->
            LGC.pointerType (assemGen.GetTypeRep(assemGen.ObjectTypeDef).InstanceVarsType) 0u
        | FAP.TypeBlob.String -> noImpl()
        | FAP.TypeBlob.ValueType ty -> noImpl()
        | FAP.TypeBlob.Var _ -> noImpl()

        // the following are also in type spec
        | FAP.TypeBlob.Ptr (custMods, tyOpt) -> noImpl()
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
            match ty.AsTypeBlob() with
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
/// to detect when this truncation results in a value that doesn�t correctly represent
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
and StackItem(bldr:LGC.BuilderRef, valueRef:LGC.ValueRef, stackType:FAP.StackType, typeBlobOpt:option<TyBlob>) =
    interface FAP.StackTyped with member x.StackType = stackType

    member x.ValueRef = valueRef

    static member FromType
            (bldr : LGC.BuilderRef)
            (valueRef : LGC.ValueRef)
            (ty : FAP.TypeDefRefOrSpec)
            : StackItem =
        new StackItem(bldr, valueRef, ty.AsIntermediateType(), ty.AsTypeBlob())

    static member FromParameter
            (bldr : LGC.BuilderRef)
            (value : LGC.ValueRef)
            (param : FAP.Parameter)
            : StackItem =

        let noImpl() = failwithf "StackItem.StackItemFromParameter: no implementation yet for %A" param
        match param.Type.pType with
        | FAP.ParamType.TypedByRef -> noImpl()
        | FAP.ParamType.MayByRefTy mayByRefTy ->
            if mayByRefTy.isByRef then
                noImpl()
            new StackItem(bldr, value, param.Type.AsIntermediateType(), Some mayByRefTy.ty)

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
            new StackItem(bldr, value, local.AsIntermediateType(), Some specLocalVar.mayByRefType.ty)

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
            new StackItem(bldr, valueRef, retTy.AsIntermediateType(), Some mayByRefTy.ty)

    static member FromField
            (bldr : LGC.BuilderRef)
            (valueRef : LGC.ValueRef)
            (field : FAP.FieldDef)
            : StackItem =

        let fSig = field.Signature
        let noImpl() = failwithf "StackItem.FromField: no implementation for: %A" fSig
        if not fSig.customMods.IsEmpty then
            noImpl()
        // TODO if we add a second StackItem constructors we can probably get rid of all of these
        // AsIntermediateType functions
        new StackItem(bldr, valueRef, fSig.fType.AsIntermediateType(), Some fSig.fType)

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
        | StackType.ObjectRef_ST ->
            cantConv()
            (*
            match ty with
            | StackType.ObjectRef_ST -> value
            | _ -> cantConv ()
            *)
        | StackType.ManagedPointer_ST ->
            cantConv()
            (*
            match ty with
            | StackType.ManagedPointer_ST -> value
            | _ -> cantConv ()
            *)

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

            match asTy.AsTypeBlob() with
            | None -> noImpl()
            | Some asTy -> x.AsTypeBlob assemGen asTy

    member x.AsTypeBlob (assemGen:AssemGen) (tyBlob:TyBlob) : LGC.ValueRef =
        // TODO we should have more checks here. Especially where we return the naked value ref.
        let noImpl() = failwithf "StackItem.AsTypeBlob: no implementation for: %A -> %A" typeBlobOpt tyBlob

        let asClass (asTy : FAP.TypeDefRefOrSpec) =
            match typeBlobOpt with
            | None -> valueRef
            | Some fromTyBlob ->
                let asTy =
                    match asTy with
                    | :? FAP.TypeDefOrRef as asTy -> asTy.Resolve()
                    | _ -> noImpl()
                match fromTyBlob with
                | TyBlob.Class fromTy ->
                    match fromTy with
                    | :? FAP.TypeDefOrRef as fromTy ->
                        let fromTy = fromTy.Resolve()
                        if fromTy = asTy then
                            valueRef
                        else
                            let ptrTy = LGC.pointerType (assemGen.GetTypeRep(asTy).InstanceVarsType) 0u
                            LGC.buildBitCast bldr valueRef ptrTy ""
                    | _ ->
                        noImpl()
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
        | TyBlob.String -> noImpl()
        | TyBlob.Ptr _ -> valueRef
        | TyBlob.ValueType _ -> noImpl()
        | TyBlob.Object -> asClass assemGen.ObjectTypeDef
        | TyBlob.Class ty -> asClass ty
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

and MethodRep(typeRep : TypeRep, methDef : FAP.MethodDef) =
    let assemGen = typeRep.AssemGen
    let moduleRef = assemGen.ModuleRef

    let makeNewObj (bldr : LGC.BuilderRef) (ctor : FAP.Method) (args : StackItem list) =
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
                item.AsParam assemGen allParams.[i].Type
            let args = newObj :: List.mapi stackItemToArg args
            LC.buildCall bldr ctorRef (Array.ofList args) "" |> ignore
            
            // TODO is this type valid? it was cut-and-paste from my old code
            let ty : TyBlob =
                match decTy.AsTypeBlob() with
                | None -> failwith "cannot build a constructor for an interface!"
                | Some ty ->
                    if decTy.IsValueType then
                        TyBlob.PtrTo ty
                    else
                        ty
            new StackItem(bldr, newObj, ty.AsIntermediateType(), Some ty)

    let declareMethod() : LGC.ValueRef =

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
                    methDef.DeclaringType.FullName + "::" + methDef.Name

            let fn = LGC.addFunction moduleRef fnName funcTy
        
            Array.iteri (nameFunParam fn) methDef.AllParameters
        
            fn
        | None ->
            failwith "implement declareMethod with None body"

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
                goNextStackItem (new StackItem(bldr, value, pushType(), None))

            let noImpl() = failwithf "instruction <<%A>> not implemented" inst
            let unexpPush() = failwithf "unexpected push types <<%A>> for instruction <<%A>>" pushType inst
            let unexpPop() = failwithf "unexpected pop types <<%A>> for instruction <<%A>>" poppedStack inst

            let brBool (nonZeroBB : int) (zeroBB : int) =
                match poppedStack with
                | [value] ->
                    // TODO would be more efficient to have custom test per size
                    let valToTest = value.AsInt false PrimSizeBytes.Eight
                    let zero = LGC.constInt (LGC.int64Type()) 0uL false
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
                let args = List.mapi stackItemToArg (List.rev poppedStack)
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

            | Inst.Ldarga argIndex -> noImpl()
            | Inst.LdcI4 i ->
                let constResult = LGC.constInt int32Ty (uint64 i) false // TODO correct me!!
                goNextValRef constResult

            | Inst.LdcI8 i -> noImpl()
            | Inst.LdcR4 r -> noImpl()
            | Inst.LdcR8 r ->
                let constResult = LGC.constReal doubleTy r
                goNextValRef constResult
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
            | Inst.Ldstr str -> noImpl()
            | Inst.Mul ->
                // The mul instruction multiplies value1 by value2 and pushes
                // the result on the stack. Integral operations silently
                // truncate the upper bits on overflow (see mul.ovf).
                // TODO: For floating-point types, 0 � infinity = NaN.
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
                    let caseInts =
                        [|for i in 0 .. blockIndexes.Length - 1 ->
                            LGC.constInt int32Ty (uint64 i) false|]
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
            | Inst.Throw -> noImpl()
            | Inst.Ldfld (unalignedOpt, volatilePrefix, field) ->
                match poppedStack with
                | [selfPtr] ->
                    let field = field.Resolve()
                    
                    if unalignedOpt.IsSome || volatilePrefix then
                        noImpl()

                    let decTy = field.DeclaringType
                    let fieldIndex = Array.findIndex (fun f -> f = field) decTy.InstanceFields
                    let fieldIndex = fieldIndex + decTy.InheritedInstanceFields.Length

                    // OK now we need to load the field
                    // TODO this doesn't seem to work. Figure out why
                    //let selfPtrVal = selfPtr.AsPointerTo(assemGen, decTy)
                    let selfPtrVal = selfPtr.ValueRef
                    let fieldName = field.Name
                    let fieldPtr = LGC.buildStructGEP bldr selfPtrVal (uint32 fieldIndex) (fieldName + "Ptr")
                    let fieldValue = LGC.buildLoad bldr fieldPtr (fieldName + "Value")
                    let fieldStackItem = StackItem.FromField bldr fieldValue field
                    goNextStackItem fieldStackItem
                | _ ->
                    unexpPop()

            | Inst.Ldflda (unalignedOpt, volatilePrefix, field) -> noImpl()
            | Inst.Stfld (unalignedOpt, volatilePrefix, field) ->
                match poppedStack with
                | [value; selfPtr] ->
                    let field = field.Resolve()

                    if unalignedOpt.IsSome || volatilePrefix then
                        noImpl()

                    let decTy = field.DeclaringType
                    let fieldIndex = Array.findIndex (fun f -> f = field) decTy.InstanceFields
                    let fieldIndex = fieldIndex + decTy.InheritedInstanceFields.Length

                    // now we need to store the field
                    let fieldPtr = LGC.buildStructGEP bldr selfPtr.ValueRef (uint32 fieldIndex) (field.Name + "Ptr")
                    LGC.buildStore bldr (value.AsField assemGen field) fieldPtr |> ignore
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Inst.Ldsfld (volatilePrefix, field) -> noImpl()
            | Inst.Ldsflda (volatilePrefix, field) -> noImpl()
            | Inst.Stsfld (volatilePrefix, field) -> noImpl()
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
                    // TODO should this be changed to signed??? I think not
                    let numElemsValRef = numElems.AsNativeInt false

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

                    // TODO "None" may be the wrong thing to do here
                    goNextValRef newArrObj
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
                    let arrPtrAddr = LGC.buildStructGEP bldr arrObj.ValueRef 1u "arrPtrAddr"
                    let arrPtr = LGC.buildLoad bldr arrPtrAddr "arrPtr"
                    // TODO: make sure that index.Value is good here... will work for all native ints or int32's
                    let elemAddr = LC.buildGEP bldr arrPtr [|index.ValueRef|] "elemAddr"
                    LGC.buildStore bldr (value.AsType assemGen elemTyRef) elemAddr |> ignore

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
            | Inst.Ldtoken metaTok -> noImpl()
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
            | Inst.Ceq -> noImpl()
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

    let maybeGenMethodBody (methodVal : LGC.ValueRef) : unit =

        match methDef.MethodBody with
        | None -> ()
        | Some methBody ->
            printfn "generating method body for: %s" methDef.Name
            
            // create the entry block
            use bldr = new LC.Builder(LGC.appendBasicBlock methodVal "entry")
            let args = [|
                for p in methDef.AllParameters ->
                    let llvmTy = TypeUtil.LLVMVarTypeOfParam assemGen p.Type
                    LGC.buildAlloca bldr llvmTy (p.Name + "_paramAlloca")
            |]
            for i = 0 to args.Length - 1 do
                LGC.buildStore bldr (LGC.getParam methodVal (uint32 i)) args.[i] |> ignore
            let locals = [|
                for localVarSig in methBody.locals ->
                    let llvmTy = TypeUtil.LLVMVarTypeOfLocalVar assemGen localVarSig
                    LGC.buildAlloca bldr llvmTy "localAlloca"
            |]

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
        new DefAndImpl<LGC.ValueRef>() with
            member x.Define() = declareMethod()
            member x.Implement vr = maybeGenMethodBody vr
    }

    member x.ValueRef : LGC.ValueRef = valueRefDefAndImpl.Value

and TypeRep (modRef : LGC.ModuleRef, typeDef : FAP.TypeDef, assemGen : AssemGen) =
    let methRepMap = new Dict<FAP.MethodDef, MethodRep>()
    let structNamed name = LGC.structCreateNamed (LGC.getModuleContext modRef) name
    let staticRef = {
        new DefAndImpl<LGC.TypeRef>() with
            member x.Define() = structNamed (typeDef.FullName + "Static")
            member x.Implement vr =
                let staticFields = [|
                    for f in typeDef.StaticFields ->
                        TypeUtil.LLVMVarTypeOfFieldDef assemGen f
                |]
                LC.structSetBody vr staticFields false
    }
    let staticVarsGlobal = lazy(LGC.addGlobal modRef staticRef.Value (typeDef.FullName + "Global"))
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
    
    member x.AssemGen : AssemGen = assemGen
    member x.InstanceVarsType = instanceRef.Value
    member x.StaticVarsType = staticRef.Value
    member x.StaticVarsGlobal = staticVarsGlobal.Force()
    member x.GetMethRep (md : FAP.MethodDef) : MethodRep =
        if methRepMap.ContainsKey md then
            methRepMap.[md]
        else
            let mr = new MethodRep(x, md)
            methRepMap.[md] <- mr
            mr

and AssemGen (modRef : LGC.ModuleRef, assembly : FAP.Assembly) =
    let typeRepMap = new Dict<FAP.TypeDef, TypeRep>()

    let objectTypeDef = lazy (
        let mscorlib = assembly.AssemblyResolution.Mscorlib
        match mscorlib.TypeDefNamed (Some "System") "Object" with
        | None -> failwith "failed to located System.Object type definition"
        | Some td -> td
    )

    member x.Assembly : FAP.Assembly = assembly
    member x.ObjectTypeDef : FAP.TypeDef = objectTypeDef.Value
    member x.ModuleRef : LGC.ModuleRef = modRef
    member x.GetTypeRep (ty:FAP.TypeDefRefOrSpec) : TypeRep =
        match ty with
        | :? FAP.TypeDefOrRef as ty ->
            let ty = ty.Resolve()
            if typeRepMap.ContainsKey ty then
                typeRepMap.[ty]
            else
                let tr = new TypeRep(modRef, ty, x)
                typeRepMap.[ty] <- tr
                tr
        | _ ->
            failwithf "GetTypeRep: not yet implemented for %A" ty

let genMainFunction
        (assemGen : AssemGen)
        (methDef : FAP.MethodDef)
        (llvmModuleRef : LGC.ModuleRef)
        : unit =
    failwith "impl main fun generation"

let genTypeDefs (llvmModuleRef : LGC.ModuleRef) (assem : FAP.Assembly) : unit =
    let assemGen = new AssemGen(llvmModuleRef, assem)

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
