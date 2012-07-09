module Fig.LLVMCodeGen

(*
open Fig.CecilExt

open Mono.Cecil
open Mono.Cecil.Cil
*)

module FAP = Fig.AssemblyParser
module FAR = Fig.AssemblyResolution
module FIO = Fig.IOUtil

module LGC = LLVM.Generated.Core
module LC = LLVM.Core
module LE = LLVM.Extra

type Inst = FAP.AbstInst
type StackType = FAP.StackType
type StackTyped = FAP.StackTyped
type TyBlob = FAP.TypeBlob

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
    | StackType.Int32_ST | StackType.Float32_ST ->
        PrimSizeBytes.Four
    | StackType.Int64_ST | StackType.Float64_ST ->
        PrimSizeBytes.Eight
    | StackType.NativeInt_ST | StackType.ObjectRef_ST | StackType.ManagedPointer_ST ->
        // TODO not sure about objectref... and what about value types?
        nativeIntSize

let llvmIntTypeSized = function
    | PrimSizeBytes.One -> LGC.int8Type ()
    | PrimSizeBytes.Two -> LGC.int16Type ()
    | PrimSizeBytes.Four -> LGC.int32Type ()
    | PrimSizeBytes.Eight -> LGC.int64Type ()
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
type StackItem (bldr:LGC.BuilderRef, value:LGC.ValueRef, ty:StackType, tyDefOpt:FAP.TypeDef option) =
    
    static member StackItemFromAny (bldr:LGC.BuilderRef, value:LGC.ValueRef, ty:FAP.TypeDef) =
        //let ty = ty.Resolve()

        let noImpl () = failwithf "cannot convert %A into a stack item" ty

        match ty.AsTypeBlob() with
        | None -> noImpl()
        | Some tb ->
            match tb with
            | TyBlob.Boolean | TyBlob.Char | TyBlob.U1 | TyBlob.U2 ->
                let value = LGC.buildZExt bldr value (LGC.int32Type()) "extendedInt"
                new StackItem(bldr, value, StackType.Int32_ST, Some ty)
            | TyBlob.I1 | TyBlob.I2 ->
                let value = LGC.buildSExt bldr value (LGC.int32Type()) "extendedInt"
                new StackItem(bldr, value, StackType.Int32_ST, Some ty)
            | TyBlob.I4 | TyBlob.U4 -> new StackItem(bldr, value, StackType.Int32_ST, Some ty)
            | TyBlob.I8 | TyBlob.U8 -> new StackItem(bldr, value, StackType.Int64_ST, Some ty)
            | TyBlob.R4 -> noImpl ()
            | TyBlob.R8 -> new StackItem(bldr, value, StackType.Float32_ST, Some ty)
            | TyBlob.String -> noImpl ()
            | TyBlob.Ptr _ -> new StackItem(bldr, value, StackType.ManagedPointer_ST, Some ty)
            | TyBlob.ValueType _ ->
                noImpl ()
                // TODO have no idea if this is right
                //assemGen.[typeRef.FullName].InstanceVarsType
            | TyBlob.Class _ -> new StackItem(bldr, value, StackType.ObjectRef_ST, Some ty)
            | TyBlob.Var _ ->
                noImpl ()
            | TyBlob.Array _ -> new StackItem(bldr, value, StackType.ObjectRef_ST, Some ty)
            | TyBlob.GenericInst _
            | TyBlob.I | TyBlob.U -> new StackItem(bldr, value, StackType.NativeInt_ST, Some ty)
            | TyBlob.FnPtr _
            | TyBlob.Object
            | TyBlob.MVar _
            | TyBlob.SzArray _ ->
                noImpl ()

    static member StackItemFromInt (bldr:LGC.BuilderRef, value:LGC.ValueRef, signed:bool, size:PrimSizeBytes) =
        match size with
        | PrimSizeBytes.Eight -> new StackItem(bldr, value, StackType.Int64_ST, None)
        | PrimSizeBytes.Four -> new StackItem(bldr, value, StackType.Int32_ST, None)
        | PrimSizeBytes.Two | PrimSizeBytes.One ->
            let extFun = if signed then LGC.buildSExt else LGC.buildZExt
            let value = extFun bldr value (LGC.int32Type()) "extendedInt"
            new StackItem(bldr, value, StackType.Int32_ST, None)
        | _ -> failwith "does not compute"
    
    member x.Value = value

    member x.AsPointerTo (assemGen:AssemGen, ty:FAP.TypeDef) : LGC.ValueRef =
        //let ty = ty.Resolve()
        //let ty = toSaferType tyRef

        let noImpl () = failwithf "no implementation for creating a pointer to %A" ty
        if not ty.IsPrimitive then
            // TODO how should we implement for non primitives
            noImpl ()
        let ptrTy = LGC.pointerType (TypeUtil.LLVMVarTypeOf assemGen ty) 0u

        // TODO is this really the way to do this? maybe the types should be normalized on construction
        match LGC.getTypeKind (LGC.typeOf x.Value) with
        | LGC.TypeKind.IntegerTypeKind ->
            LGC.buildIntToPtr bldr x.Value ptrTy "ptrFromInt"
        | LGC.TypeKind.PointerTypeKind ->
            LGC.buildBitCast bldr x.Value ptrTy "ptr"
        | tk ->
            failwithf "cannot convert type kind %A to pointer" tk

    member x.AsInvokable(assemGen:AssemGen, ty:FAP.TypeDef) : LGC.ValueRef =
        //let tyRef = tyRef.Resolve()
        //let ty = toSaferType tyRef
        //let ty = ty.Resolve()

        let noImpl () = failwith "no implementation for creating an invokable from %A" ty
        if not ty.IsPrimitive then
            // TODO how should we implement for non primitives
            noImpl ()
        let ptrTy = LGC.pointerType (TypeUtil.LLVMInvokableTypeOf assemGen ty) 0u

        // TODO is this really the way to do this? maybe the types should be normalized on construction
        match LGC.getTypeKind (LGC.typeOf x.Value) with
        | LGC.TypeKind.IntegerTypeKind ->
            LGC.buildIntToPtr bldr x.Value ptrTy "invokablePtrFromInt"
        | LGC.TypeKind.PointerTypeKind ->
            LGC.buildBitCast bldr x.Value ptrTy "invokablePtr"
        | tk ->
            failwithf "cannot convert type kind %A to pointer" tk

    member x.AsTypeReference (assemGen:AssemGen, ty:FAP.TypeDef) =
        //let tyRef = tyRef.Resolve()
        //let ty = toSaferType tyRef

        let noImpl () = failwithf "cannot convert as type reference %A" ty

        match ty.AsTypeBlob() with
        | None -> noImpl()
        | Some tb ->
            match tb with
            | TyBlob.Boolean | TyBlob.U1 -> x.AsInt(false, PrimSizeBytes.One)
            | TyBlob.Char -> x.AsInt(false, PrimSizeBytes.Two)
            | TyBlob.U2 -> x.AsInt(false, PrimSizeBytes.Two)
            | TyBlob.I1 -> x.AsInt(true, PrimSizeBytes.One)
            | TyBlob.I2 -> x.AsInt(true, PrimSizeBytes.Two)
            | TyBlob.I4 -> x.AsInt(true, PrimSizeBytes.Four)
            | TyBlob.U4 -> x.AsInt(false, PrimSizeBytes.Four)
            | TyBlob.I8 -> x.AsInt(true, PrimSizeBytes.Eight)
            | TyBlob.U8 -> x.AsInt(false, PrimSizeBytes.Eight)
            | TyBlob.R4 -> x.AsFloat(true, false)
            | TyBlob.R8 -> x.AsFloat(true, true)
            | TyBlob.String -> noImpl ()
            | TyBlob.Ptr _ -> value
            | TyBlob.ValueType _ | TyBlob.Class _ | TyBlob.Object ->
                match tyDefOpt with
                | None -> value
                | Some thisTy ->
                    if thisTy = ty then
                        value
                    else
                        LGC.buildBitCast bldr value (LGC.pointerType assemGen.ClassMap.[ty].InstanceVarsType 0u) ""
            | TyBlob.Var _ -> noImpl ()
            | TyBlob.Array _ -> value
            | TyBlob.GenericInst _
            | TyBlob.I -> x.AsNativeInt true
            | TyBlob.U -> x.AsNativeInt false
            | TyBlob.FnPtr _
            | TyBlob.MVar _
            | TyBlob.SzArray _ ->
                noImpl ()

    member x.AsStackType (asTy:StackType) =
        let cantConv () = failwithf "cannot convert %A to %A" ty asTy
        match asTy with
        | StackType.Int32_ST -> x.AsInt (false, PrimSizeBytes.Four)
        | StackType.Int64_ST -> x.AsInt (false, PrimSizeBytes.Eight)
        | StackType.NativeInt_ST -> x.AsNativeInt false
        | StackType.Float32_ST -> x.AsFloat(true, false)
        | StackType.Float64_ST -> x.AsFloat(true, true)
        | StackType.ObjectRef_ST ->
            match ty with
            | StackType.ObjectRef_ST -> value
            | _ -> cantConv ()
        | StackType.ManagedPointer_ST ->
            match ty with
            | StackType.ManagedPointer_ST -> value
            | _ -> cantConv ()

    member x.AsInt (asSigned:bool, asSize:PrimSizeBytes) =
        let size = sizeOfStackType ty
        match ty with
        | FAP.Int_ST ->
            if asSize = size then
                value
            elif asSize < size then
                LGC.buildTrunc bldr value (llvmIntTypeSized asSize) "truncInt"
            else
                let extFun = if asSigned then LGC.buildSExt else LGC.buildZExt
                extFun bldr value (llvmIntTypeSized asSize) "extendedInt"
        | FAP.Float_ST ->
            LGC.buildFPToSI bldr value (llvmIntTypeSized asSize) "truncatedFP"
        | FAP.ObjectRef_ST ->
            LGC.buildPtrToInt bldr value (llvmIntTypeSized asSize) "ptrAsInt"
        | _ ->
            failwithf "TODO implement int conversion for %A" ty

    member x.AsNativeInt (asSigned:bool) = x.AsInt (asSigned, nativeIntSize)

    member x.AsFloat (asSigned:bool, asLong:bool) =
        let asTy = if asLong then LGC.doubleType() else LGC.floatType()
        match ty with
        | FAP.Float32_ST ->
            if asLong
            then LGC.buildFPExt bldr value asTy "extendedFloat"
            else value
        | FAP.Float64_ST ->
            if asLong
            then value
            else LGC.buildFPTrunc bldr value asTy "truncFloat"
        | FAP.Int_ST ->
            if asSigned
            then LGC.buildSIToFP bldr value asTy "convVal"
            else LGC.buildUIToFP bldr value asTy "convVal"
        | _ -> failwithf "implicit cast from %A to float32 is not allowed" ty

    interface StackTyped with
        member x.StackType = ty

and TypeUtil () =

    static member LLVMVarTypeOf (assemGen : AssemGen) (ty : FAP.TypeDef) =

        let noImpl () = failwithf "no impl for %A type yet" ty
    
        match ty.AsTypeBlob() with
        | None -> noImpl()
        | Some tb ->
            match tb with
            //| Void -> LGC.voidType ()

            // TODO probably need a separate function for getting stack type vs normal type
            | TyBlob.Boolean -> LGC.int8Type ()
            | TyBlob.Char -> LGC.int16Type ()
            | TyBlob.I1 | TyBlob.U1 -> LGC.int8Type ()
            | TyBlob.I2 | TyBlob.U2 -> noImpl ()
            | TyBlob.I4 | TyBlob.U4 -> LGC.int32Type ()
            | TyBlob.I8 | TyBlob.U8 -> LGC.int64Type ()
            | TyBlob.R4 -> noImpl ()
            | TyBlob.R8 -> LGC.doubleType ()
            | TyBlob.String -> noImpl ()
            | TyBlob.Ptr (custMods, elementTyBlob) ->
                match elementTyBlob with
                | Some (TyBlob.Class classTy) ->
                    LGC.pointerType assemGen.ClassMap.[elementTyBlob].InstanceVarsType 0u
                | _ ->
                    noImpl()
            (*| ByReference byRefType ->
                LGC.pointerType assemGen.ClassMap.[byRefType.ElementType].InstanceVarsType 0u*)
            | TyBlob.ValueType typeRef ->
                // TODO have no idea if this is right
                assemGen.ClassMap.[typeRef].InstanceVarsType
            | TyBlob.Class _ | TyBlob.Object ->
                LGC.pointerType assemGen.ClassMap.[ty].InstanceVarsType 0u
            | TyBlob.Var _ ->
                noImpl ()
            | TyBlob.Array (elemTy, arrShape) ->
                if arrShape.rank = 1u then
                    //let loBound = if arrShape.loBounds.Length = 0 then 0 else arrShape.loBounds.[0]
                    //let dim0 = arrTy.Dimensions.[0]
                    match arrShape.loBounds, arrShape.sizes with
                    | (([||] | [|0|]), [||]) ->
                        // LLVM docs say:
                        // "... 'variable sized array' addressing can be implemented in LLVM
                        // with a zero length array type". So, we implement this as a struct
                        // which contains a length element and an array element
                        let elemTy = TypeUtil.LLVMVarTypeOf assemGen elemTy
                        let basicArrTy = LGC.pointerType elemTy 0u
                        // FIXME array len should correspond to "native unsigned int" not int32
                        LGC.pointerType (LC.structType [|LGC.int32Type (); basicArrTy|] false) 0u
                    | lowerBound, upperBound ->
                        failwithf "dont know how to deal with given array shape yet %A->%A" lowerBound upperBound
                else
                    failwithf "arrays of rank %i not yet implemented" arrShape.rank
            | TyBlob.GenericInst _ -> noImpl()
            //| TypedByReference -> noImpl ()
            | TyBlob.I | TyBlob.U -> llvmIntTypeSized nativeIntSize
            | TyBlob.FnPtr _
            | TyBlob.MVar _
            | TyBlob.SzArray _
            (*| RequiredModifier _
            | OptionalModifier _
            | Sentinel _
            | Pinned _*) ->
                noImpl ()

    static member LLVMVarTypeOfRetType (assemGen : AssemGen) (rt : FAP.RetType) =
        let noImpl() = failwithf "no impl for return type %A yet" rt

        match rt with
        | {FAP.RetType.customMods = []; FAP.RetType.rType = rType} ->
            match rType with
            | FAP.RetTypeKind.MayByRefTy {FAP.MaybeByRefType.isByRef = false; ty = ty} ->
                TypeUtil.LLVMVarTypeOfTypeBlob assemGen ty
            | _ -> noImpl()
        | _ -> noImpl()

    static member LLVMVarTypeOfParam (assemGen : AssemGen) (p : FAP.Param) =
        let noImpl() = failwithf "no impl for param %A yet" p

        match p with
        | {FAP.Param.customMods = []; FAP.Param.pType = FAP.MayByRefTy ({FAP.MaybeByRefType.isByRef = false; FAP.MaybeByRefType.ty = ty})} ->
            TypeUtil.LLVMVarTypeOfTypeBlob assemGen ty
        | _ ->
            noImpl()

    static member LLVMVarTypeOfTypeBlob (assemGen : AssemGen) (ty : FAP.TypeBlob) =
        let noImpl () = failwithf "no impl for %A type yet" ty
        match ty with
        | FAP.TypeBlob.Boolean -> LGC.int8Type()
        | FAP.TypeBlob.Char -> LGC.int16Type()
        | FAP.TypeBlob.I1 | FAP.TypeBlob.U1 -> LGC.int8Type()
        | FAP.TypeBlob.I2 | FAP.TypeBlob.U2 -> noImpl()
        | FAP.TypeBlob.I4 | FAP.TypeBlob.U4 -> LGC.int32Type()
        | FAP.TypeBlob.I8 | FAP.TypeBlob.U8 -> LGC.int64Type()
        | FAP.TypeBlob.R4 -> noImpl()
        | FAP.TypeBlob.R8 -> LGC.doubleType()
        | FAP.TypeBlob.I | FAP.TypeBlob.U -> llvmIntTypeSized nativeIntSize
        | FAP.TypeBlob.Class ty -> LGC.pointerType assemGen.ClassMap.[ty].InstanceVarsType 0u
        | FAP.TypeBlob.MVar _ -> noImpl()
        | FAP.TypeBlob.Object -> noImpl() // NOTE this is implemented in the old version
        | FAP.TypeBlob.String -> noImpl()
        | FAP.TypeBlob.ValueType ty ->
            // TODO have no idea if this is right
            assemGen.ClassMap.[typeRef].InstanceVarsType
        | FAP.TypeBlob.Var _ -> noImpl()

        // the following are also in type spec
        | FAP.TypeBlob.Ptr (custMods, tyOpt) -> //of List<CustomModBlob> * Option<TypeBlob>
            match custMods, tyOpt with
            | [], Some ty ->
                LGC.pointerType assemGen.ClassMap.[ty].InstanceVarsType 0u
            | _ -> noImpl()
        | FAP.TypeBlob.FnPtr _ -> noImpl()
        | FAP.TypeBlob.Array (ty, arrShape) ->
            if arrShape.rank = 1u then
                //let dim0 = arrTy.Dimensions.[0]
                match arrShape.loBounds, arrShape.sizes with
                | ([||] | [|0|]), [||] ->
                    // LLVM docs say:
                    // "... 'variable sized array' addressing can be implemented in LLVM
                    // with a zero length array type". So, we implement this as a struct
                    // which contains a length element and an array element
                    let elemTy = TypeUtil.LLVMVarTypeOf assemGen ty
                    let basicArrTy = LGC.pointerType elemTy 0u
                    // FIXME array len should correspond to "native unsigned int" not int32
                    LGC.pointerType (LC.structType [|LGC.int32Type(); basicArrTy|] false) 0u
                | lowerBound, sizes ->
                    failwithf "dont know how to deal with given array shape yet %A->%A" lowerBound sizes
            else
                failwithf "arrays of rank %i not yet implemented" arrShape.rank
        | FAP.TypeBlob.SzArray (custMods, ty) -> noImpl()
        // GenericInst bool isClass with false indicating valuetype
        | FAP.TypeBlob.GenericInst _ -> noImpl()

    static member LLVMNewableTypeOf (assemGen : AssemGen) (ty : FAP.TypeDef) =

        let noImpl () = failwithf "no allocable type impl for %A type yet" ty

        match ty.AsTypeBlob() with
        | None -> noImpl()
        | Some tb ->
            match tb with
            //| Void -> LGC.voidType ()

            // TODO probably need a separate function for getting stack type vs normal type
            | TyBlob.Boolean -> LGC.int8Type ()
            | TyBlob.Char -> LGC.int16Type ()
            | TyBlob.I1 | TyBlob.U1 -> LGC.int8Type ()
            | TyBlob.I2 | TyBlob.U2 -> noImpl ()
            | TyBlob.I4 | TyBlob.U4 -> LGC.int32Type ()
            | TyBlob.I8 | TyBlob.U8 -> LGC.int64Type ()
            | TyBlob.R4 -> noImpl ()
            | TyBlob.R8 -> LGC.doubleType ()
            | TyBlob.String -> noImpl ()
            | TyBlob.Ptr _ -> noImpl ()
            //| ByReference _ -> noImpl ()
            | TyBlob.ValueType _ | TyBlob.Class _ | TyBlob.Object ->
                assemGen.ClassMap.[ty].InstanceVarsType
            | TyBlob.Var _ ->
                noImpl ()
            | TyBlob.Array _ ->
                noImpl ()
            | TyBlob.GenericInst _ -> noImpl()
            //| TypedByReference -> noImpl ()
            | TyBlob.I | TyBlob.U -> llvmIntTypeSized nativeIntSize
            | TyBlob.FnPtr _
            | TyBlob.MVar _ ->
                noImpl()
            | TyBlob.SzArray _ ->
                noImpl()
            //| RequiredModifier _
            //| OptionalModifier _
            //| Sentinel _
            //| Pinned _ ->
            //    noImpl ()

    static member LLVMInvokableTypeOf (assemGen : AssemGen) (ty : FAP.TypeDef) =
        let newableTy = TypeUtil.LLVMNewableTypeOf assemGen ty
        LGC.pointerType newableTy 0u

and AssemGen (modRef : LGC.ModuleRef, assem : FAP.Assembly) as x =
    let classMap = new ClassMap(modRef, x)

    member x.ClassMap : ClassMap = classMap

    member x.AssemDef : FAP.Assembly = assem

and ClassMap (modRef : LGC.ModuleRef, assemGen : AssemGen) =
    let classDict = new Dictionary<string * string option * string * string, ClassTypeRep>()

    member x.Item
        with get (tr : FAP.TypeDefOrRef) : ClassTypeRep =
            let td = tr.Resolve()

            // TODO make sure this addresses concerns mentioned in:
            // http://groups.google.com/group/mono-cecil/browse_thread/thread/2d59759860f31458
            let key = (td.Name, td.Namespace, td.Module.Name, td.Assembly.Name)
            if classDict.ContainsKey key then
                classDict.[key]
            else
                let classTyRep = new ClassTypeRep(modRef, td, assemGen)
                classDict.[key] <- classTyRep
                classTyRep

    member x.Item
        with get (mr : FAP.Method) : ClassTypeRep =
            x.[mr.Resolve().DeclaringType]

and ClassTypeRep (modRef : LGC.ModuleRef, typeDef : FAP.TypeDef, assemGen : AssemGen) as x =
    let structNamed name = LGC.structCreateNamed (LGC.getModuleContext modRef) name
    let staticRef = {
        new DefAndImpl<LGC.TypeRef>() with
            member x.Define() = structNamed (typeDef.FullName + "Static")
            member x.Implement vr =
                let staticFields =
                    [|for f in typeDef.StaticFields ->
                        TypeUtil.LLVMVarTypeOf assemGen f.FieldType|]
                LC.structSetBody vr staticFields false
    }
    let instanceRef = {
        new DefAndImpl<LGC.TypeRef>() with
            member x.Define() = structNamed (typeDef.FullName + "Instance")
            member x.Implement vr =
                let instanceFields = [|
                    //for f in typeDef.AllInstanceFields ->
                    for f in typeDef.InstanceFields ->
                        TypeUtil.LLVMVarTypeOf assemGen f.FieldType
                |]
                LC.structSetBody vr instanceFields false
    }
    let staticVars = lazy(LGC.addGlobal modRef staticRef.Value (typeDef.FullName + "Global"))
    let methMap = new MethodMap(modRef, assemGen, x)

    member x.InstanceVarsType = instanceRef.Value
    member x.StaticVarsType = staticRef.Value
    member x.StaticVars = staticVars.Force()
    member x.MethodMap : MethodMap = methMap
    member x.TypeDef : FAP.TypeDef = typeDef

and MethodMap (modRef : LGC.ModuleRef, assemGen : AssemGen, classRep : ClassTypeRep) =
    let methDict = new Dictionary<string * bool * string, MethodRep>()

    member x.Item
        with get (methRef : FAP.Method) : MethodRep =
            let methDef = methRef.Resolve()

            if methDef.DeclaringType.FullName <> classRep.TypeDef.FullName then
                failwithf
                    "error looking up %s::%s: method map for %s cannot be used to lookup a class from %s"
                    methDef.DeclaringType.FullName
                    methDef.Name
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

and MethodRep (moduleRef : LGC.ModuleRef, methDef : FAP.MethodDef, assemGen : AssemGen) =
    
    let makeNewObj (bldr : LGC.BuilderRef) (methRef : FAP.Method) (args : StackItem list) =
        // TODO implement GC along with object/class initialization code
        // FIXME naming is all screwed up! fix it
        let methDef = methRef.Resolve ()
        if not methDef.IsCtor then
            failwith "expected a .ctor here"
        else
            let funRef = assemGen.ClassMap.[methDef].MethodMap.[methDef].ValueRef
            let llvmTy = assemGen.ClassMap.[methDef.DeclaringType].InstanceVarsType
            let newObj = LGC.buildMalloc bldr llvmTy ("new" + methDef.DeclaringType.FullName)
            let stackItemToArg (i:int) (item:StackItem) =
                item.AsTypeReference(assemGen, methDef.AllParameters.[i].ParameterType)
            let args = newObj :: List.mapi stackItemToArg args
            LC.buildCall bldr funRef (Array.ofList args) "" |> ignore
            let ty : FAP.TypeRef =
                if methDef.DeclaringType.IsValueType then
                    new PointerType(methDef.DeclaringType)
                else
                    methDef.DeclaringType
            StackItem.StackItemFromAny(bldr, newObj, ty)

    let rec genInstructions
            (bldr : LGC.BuilderRef)
            (methodVal : LGC.ValueRef)
            (args : LGC.ValueRef array)
            (locals : LGC.ValueRef array)
            (llvmBlocks : LGC.BasicBlockRef array)
            (methDef : FAP.MethodDef)
            (blockIndex : int)
            (insts : Inst list)
            (stackVals : StackItem list) =
            (*
            (blockMap : Map<int, LGC.BasicBlockRef>)
            (ilBB : BasicBlock)
            (stackVals : StackItem list)
            (insts : AnnotatedInstruction list) =
            *)

        match insts with
        | [] -> ()
        | inst :: instTail ->
            //printfn "Inst: %A" inst.Instruction

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
                genInstructions bldr methodVal args locals llvmBlocks methDef blockIndex instTail stackVals
            let goNextStackItem (si : StackItem) =
                goNext (si :: stackTail)
            let goNextValRef (value : LGC.ValueRef) (tyRefOpt : FAP.TypeDef option) =
                goNextStackItem (new StackItem(bldr, value, pushType(), tyRefOpt))

            let noImpl () = failwithf "instruction <<%A>> not implemented" inst
            let unexpPush () = failwithf "unexpected push types <<%A>> for instruction <<%A>>" pushType inst
            let unexpPop () = failwithf "unexpected pop types <<%A>> for instruction <<%A>>" poppedStack inst

            let brBool (nonZeroBB : int) (zeroBB : int) =
                match poppedStack with
                | [value] ->
                    // TODO would be more efficient to have custom test per size
                    let valToTest = value.AsInt(false, PrimSizeBytes.Eight)
                    let zero = LGC.constInt (LGC.int64Type()) 0uL false
                    let isZero = LGC.buildICmp bldr LGC.IntPredicate.IntEQ valToTest zero "isZero"
                    let nonZeroBlk = llvmBlocks.[nonZeroBB]
                    let zeroBlk = llvmBlocks.[zeroBB]
                    LGC.buildCondBr bldr isZero zeroBlk nonZeroBlk |> ignore
                | _ ->
                    failwithf "expected a single value to be popped from the stack for: %A" inst

            match inst with
            // Basic
            | Inst.Add ->
                // The add instruction adds value2 to value1 and pushes the result
                // on the stack. Overflow is not detected for integral operations
                // (but see add.ovf); floating-point overflow returns +inf or -inf.
                match poppedStack with
                | [value2; value1] ->
                    let v1 = value1.AsStackType(pushType())
                    let v2 = value2.AsStackType(pushType())
                    let addResult =
                        match pushType() with
                        | FAP.Float_ST -> LGC.buildFAdd bldr v1 v2 "tmpFAdd"
                        | FAP.Int_ST -> LGC.buildAdd bldr v1 v2 "tmpAdd"
                        | _ -> unexpPush()
                    goNextValRef addResult None
                | _ -> unexpPop()

            | Inst.AddOvf -> noImpl ()
            | Inst.AddOvfUn -> noImpl ()
            | Inst.And -> noImpl ()
            | Inst.Div ->
                match poppedStack with
                | [value2; value1] ->
                    let v1 = value1.AsStackType (pushType())
                    let v2 = value2.AsStackType (pushType())
                    let divResult =
                        match pushType() with
                        | FAP.Float_ST -> LGC.buildFDiv bldr v1 v2 "tmpFDiv"
                        | FAP.Int_ST -> LGC.buildSDiv bldr v1 v2 "tmpDiv"
                        | _ -> unexpPush()
                    goNextValRef divResult None
                | _ -> unexpPop()

            | Inst.DivUn -> noImpl ()
            | Inst.Ceq -> noImpl ()
            | Inst.Cgt -> noImpl ()
            | Inst.CgtUn -> noImpl ()
            | Inst.Clt -> noImpl ()
            | Inst.CltUn -> noImpl ()

            // For conversion ops see ECMA-335 Partition III 1.5 table 8
            | Inst.ConvI1 -> noImpl ()
            | Inst.ConvI2 ->
                noImpl ()
            | Inst.ConvI4 ->
                match poppedStack with
                | [FAP.STyped FAP.Int_ST as value] ->
                    goNextValRef (value.AsInt(true, PrimSizeBytes.Four)) None
                | _ ->
                    failwithf "convi4 no impl for <<%A>>" [for x in poppedStack -> (x :> StackTyped).StackType]
            | Inst.ConvI8 -> noImpl ()
            | Inst.ConvR4 ->
                noImpl ()
            | Inst.ConvR8 ->
                match poppedStack with
                | [value] -> goNextValRef (value.AsFloat(true, true)) None
                | _ -> noImpl()

            | Inst.ConvU4 -> noImpl ()
            | Inst.ConvU8 -> noImpl ()
            | Inst.ConvU2 -> noImpl ()
            | Inst.ConvU1 -> noImpl ()
            | Inst.ConvI ->
                match poppedStack with
                | [value] -> goNextValRef (value.AsNativeInt true) None
                | _ -> noImpl()

            | Inst.ConvU -> noImpl ()

            | Inst.ConvRUn -> noImpl ()

            | Inst.ConvOvfI1Un -> noImpl ()
            | Inst.ConvOvfI2Un -> noImpl ()
            | Inst.ConvOvfI4Un -> noImpl ()
            | Inst.ConvOvfI8Un -> noImpl ()
            | Inst.ConvOvfU1Un -> noImpl ()
            | Inst.ConvOvfU2Un -> noImpl ()
            | Inst.ConvOvfU4Un -> noImpl ()
            | Inst.ConvOvfU8Un -> noImpl ()
            | Inst.ConvOvfIUn -> noImpl ()
            | Inst.ConvOvfUUn -> noImpl ()

            | Inst.ConvOvfI1 -> noImpl ()
            | Inst.ConvOvfU1 -> noImpl ()
            | Inst.ConvOvfI2 -> noImpl ()
            | Inst.ConvOvfU2 -> noImpl ()
            | Inst.ConvOvfI4 -> noImpl ()
            | Inst.ConvOvfU4 -> noImpl ()
            | Inst.ConvOvfI8 -> noImpl ()
            | Inst.ConvOvfU8 -> noImpl ()
            | Inst.ConvOvfI -> noImpl ()
            | Inst.ConvOvfU -> noImpl ()
            | Inst.Mul ->
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
                        | FAP.Float_ST -> LGC.buildFMul bldr v1 v2 "tmpFMul"
                        | FAP.Int_ST -> LGC.buildMul bldr v1 v2 "tmpMul"
                        | _ -> unexpPush()
                    goNextValRef mulResult None
                | _ -> unexpPop()

            | Inst.MulOvf -> noImpl ()
            | Inst.MulOvfUn -> noImpl ()
            | Inst.Rem -> noImpl ()
            | Inst.RemUn -> noImpl ()
            | Inst.Shl -> noImpl ()
            | Inst.Shr -> noImpl ()
            | Inst.ShrUn -> noImpl ()
            | Inst.Sub ->
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
                        | FAP.Float_ST -> LGC.buildFSub bldr v1 v2 "tmpFSub"
                        | FAP.Int_ST -> LGC.buildSub bldr v1 v2 "tmpSub"
                        | _ -> unexpPush()
                    goNextValRef subResult None
                | _ -> unexpPop()

            | Inst.SubOvf -> noImpl ()
            | Inst.SubOvfUn -> noImpl ()
            | Inst.Xor -> noImpl ()
            | Inst.Or -> noImpl ()
            | Inst.Neg -> noImpl ()
            | Inst.Not -> noImpl ()
            | Inst.Ldnull -> noImpl ()
            | Inst.Dup ->
                // TODO this will probably only work in some limited cases
                match poppedStack with
                | [value] -> goNext (value :: value :: stackTail)
                | _ -> unexpPop()

            | Inst.Pop ->
                match poppedStack with
                | [_] -> goNext stackTail
                | _ -> unexpPop()

            | Inst.Ckfinite -> noImpl ()
            | Inst.Nop ->
                match poppedStack with
                | [] -> goNext stackVals
                | _ -> unexpPop()
            | Inst.LdcI4 i ->
                let constResult = LGC.constInt (LGC.int32Type ()) (uint64 i) false // TODO correct me!!
                goNextValRef constResult None
            | Inst.LdcI8 i ->
                let constResult = LGC.constInt (LGC.int64Type ()) (uint64 i) false // TODO correct me!!
                goNextValRef constResult None
            | Inst.LdcR4 _ -> noImpl ()
            | Inst.LdcR8 r ->
                let constResult = LGC.constReal (LGC.doubleType ()) r
                goNextValRef constResult None
            | Inst.Ldarg paramIndex ->
                let paramDef = methDef.Parameters.[int paramIndex]
                let name = "tmp_" + paramDef.Name
                let value = LGC.buildLoad bldr args.[paramDef.Sequence] name
                goNextStackItem (StackItem.StackItemFromAny(bldr, value, paramDef.Type))

            | Inst.Ldarga paramIndex ->
                let paramDef = methDef.Parameters.[int paramIndex]
                goNextValRef args.[paramDef.Sequence] (Some paramDef.Type)
            | Inst.LdindI1 _ -> noImpl ()
            | Inst.LdindU1 _ -> noImpl ()
            | Inst.LdindI2 _ -> noImpl ()
            | Inst.LdindU2 _ -> noImpl ()
            | Inst.LdindI4 _ -> noImpl ()
            | Inst.LdindU4 _ -> noImpl ()
            | Inst.LdindI8 _ -> noImpl ()
            | Inst.LdindI _ -> noImpl ()
            | Inst.LdindR4 _ -> noImpl ()
            | Inst.LdindR8 _ -> noImpl ()
            | Inst.LdindRef _ -> noImpl ()
            | Inst.Ldloc locIndex ->
                let locIndex = int locIndex
                let local = methDef.Locals.[locIndex]
                let loadResult = LGC.buildLoad bldr locals.[locIndex] "tmp"

                goNextStackItem (StackItem.StackItemFromAny(bldr, loadResult, local))
            | Inst.Ldloca varIndex ->
                goNextValRef locals.[int varIndex] None
            | Inst.Starg argIndex ->
                match poppedStack with
                | [stackHead] ->
                    let argIndex = int argIndex
                    let argTy = methDef.AllParameters.[argIndex].Type
                    let valRef = stackHead.AsTypeReference(assemGen, argTy)
                    LGC.buildStore bldr valRef args.[argIndex] |> ignore
                    goNext stackTail
                | _ -> unexpPop()
            | Inst.StindRef _ -> noImpl ()
            | Inst.StindI1 _ -> noImpl ()
            | Inst.StindI2 _ -> noImpl ()
            | Inst.StindI4 _ -> noImpl ()
            | Inst.StindI8 _ -> noImpl ()
            | Inst.StindR4 _ -> noImpl ()
            | Inst.StindR8 _ -> noImpl ()
            | Inst.StindI _ -> noImpl ()
            | Inst.Stloc locIndex ->
                match poppedStack with
                | [stackHead] ->
                    let locIndex = int locIndex
                    let local = methDef.Locals.[locIndex]
                    let valRef = stackHead.AsTypeReference(assemGen, local)

                    LGC.buildStore bldr valRef locals.[locIndex] |> ignore
                    goNext stackTail
                | _ -> unexpPop()

            // Control transfer
            | Inst.Br bb ->
                LGC.buildBr bldr llvmBlocks.[bb] |> ignore
            | Inst.Jmp _ ->
                noImpl ()
            | Inst.Brfalse brIndex -> brBool (blockIndex + 1) brIndex
            | Inst.Brtrue brIndex -> brBool brIndex (blockIndex + 1)
            | Inst.Beq trueBB | Inst.Bge trueBB | Inst.Bgt trueBB
            | Inst.Ble trueBB | Inst.Blt trueBB | Inst.BneUn trueBB
            | Inst.BgeUn trueBB | Inst.BgtUn trueBB | Inst.BleUn trueBB
            | Inst.BltUn trueBB ->
            
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a branch"
            
                let isSigned () =
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
                    | _             -> failwith "whoa! this error should be impossible!"

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
                    brInt value1.Value value2.Value
                | _ ->
                    failwithf "branching not yet implemented for types: %A" [for x in poppedStack -> (x :> StackTyped).StackType]

            | Inst.Switch caseBlocks ->
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a branch"
            
                match poppedStack with
                | [value] ->
                    let caseInts =
                        [|for i in 0 .. caseBlocks.Length - 1 ->
                            LGC.constInt (LGC.int32Type ()) (uint64 i) false|]
                    let caseBlocks = [|for b in caseBlocks -> llvmBlocks.[b]|]
                    let target = value.AsInt(false, PrimSizeBytes.Four)
                    let fallthroughBlock = llvmBlocks.[blockIndex + 1]
                    LC.buildSwitchWithCases bldr target (Array.zip caseInts caseBlocks) fallthroughBlock
                | _ ->
                    unexpPop()

            | Inst.Ret ->
                // The evaluation stack for the current method shall be empty except for the value to be returned.
                if not stackTail.IsEmpty then
                    failwith "the value stack should be empty after a return"
                if not instTail.IsEmpty then
                    failwith "the instruction stack should be empty after a return"

                match poppedStack with
                | [] ->
                    if methDef.ReturnType.IsVoid then
                        failwith "expected a void return type"
                    LGC.buildRetVoid bldr |> ignore
                | [stackHead] ->
                    let retItem = stackHead.AsTypeReference(assemGen, methDef.ReturnType)
                    LGC.buildRet bldr retItem |> ignore
                | _ ->
                    unexpPop()

            // Method call
            | Inst.Call call ->
                // look up the corresponding LLVM function
                let methDef = call.Method.Resolve()
                let funRef = assemGen.ClassMap.[methDef].MethodMap.[methDef].ValueRef

                let stackItemToArg (i:int) (item:StackItem) =
                    item.AsTypeReference(assemGen, methDef.AllParameters.[i].Type)
                let args = List.mapi stackItemToArg (List.rev poppedStack)
                let resultName = if pushTypes.IsEmpty then "" else "callResult"
                let callResult = LC.buildCall bldr funRef (Array.ofList args) resultName
                if call.Tail then LGC.setTailCall callResult true
                if pushTypes.IsEmpty then
                    goNext stackTail
                else
                    goNextStackItem (StackItem.StackItemFromAny(bldr, callResult, methDef.ReturnType))

            | Inst.Callvirt _ -> noImpl ()
            | Inst.Calli _ -> noImpl ()
            | Inst.Ldftn _ -> noImpl ()
            | Inst.Newobj methRef -> makeNewObj bldr methRef (List.rev poppedStack) |> goNextStackItem

            // Exceptions
            | Inst.Throw -> noImpl ()
            | Inst.Endfinally -> noImpl ()
            | Inst.Endfilter -> noImpl ()
            | Inst.Leave _ -> noImpl ()
            | Inst.Rethrow -> noImpl ()

            // Object instructions
            | Inst.Ldsfld (_volatile, field) ->
                match poppedStack with
                | [] ->
                    let field = field.Resolve()

                    // TODO alignment and volitility
                    let fieldName = field.Name
                    let decTy = field.DeclaringType
                    let fieldIndex = Array.findIndex (fun f -> f = field) decTy.StaticFields

                    // OK now we need to load the field
                    let declClassRep = assemGen.ClassMap.[decTy]
                    let fieldPtr = LGC.buildStructGEP bldr declClassRep.StaticVars (uint32 fieldIndex) (fieldName + "Ptr")
                    let fieldValue = LGC.buildLoad bldr fieldPtr (fieldName + "Value")
                    let fieldStackItem = StackItem.StackItemFromAny(bldr, fieldValue, field.Signature)
                    goNextStackItem fieldStackItem
                | _ ->
                    unexpPop()

            | Inst.Ldfld (_alignment, _volatile, field) ->
                match poppedStack with
                | [selfPtr] ->
                    let field = field.Resolve()
                    
                    // TODO alignment and volitility
                    let decTy = field.DeclaringType
                    let fieldIndex = Array.findIndex (fun f -> f = field) decTy.InstanceFields
                    let fieldIndex = fieldIndex + decTy.NumInheritedInstanceFields

                    // OK now we need to load the field
                    // TODO this doesn't seem to work. Figure out why
                    //let selfPtrVal = selfPtr.AsPointerTo(assemGen, decTy)
                    let selfPtrVal = selfPtr.Value
                    let fieldName = field.Name
                    let fieldPtr = LGC.buildStructGEP bldr selfPtrVal (uint32 fieldIndex) (fieldName + "Ptr")
                    let fieldValue = LGC.buildLoad bldr fieldPtr (fieldName + "Value")
                    let fieldStackItem = StackItem.StackItemFromAny(bldr, fieldValue, field.Signature)
                    goNextStackItem fieldStackItem
                | _ ->
                    unexpPop()

            | Inst.Ldsflda _ -> noImpl ()
            | Inst.Ldflda _ -> noImpl ()
            | Inst.Stsfld (_volatilePrefix, fieldRef) ->
                match poppedStack with
                | [value] ->
                    // TODO volatility
                    let fieldName = fieldRef.FullName
                    let declaringTy = fieldRef.DeclaringType.Resolve ()
                    let staticCilFields = declaringTy.StaticFields
                    let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) staticCilFields

                    // now store the field
                    let declClassRep = assemGen.ClassMap.[declaringTy]
                    let fieldPtr = LGC.buildStructGEP bldr declClassRep.StaticVars (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                    LGC.buildStore bldr (value.AsTypeReference(assemGen, fieldRef.FieldType)) fieldPtr |> ignore
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Inst.Stfld (_unalignedPrefix, _volatilePrefix, fieldRef) ->
                match poppedStack with
                | [value; selfPtr] ->
                    // TODO alignment and volitility
                    let fieldName = fieldRef.FullName
                    let decTy = fieldRef.DeclaringType.Resolve()
                    let cilFields = decTy.InstanceFields
                    let fieldIndex = Seq.findIndex (fun (f : FieldDefinition) -> f.FullName = fieldName) cilFields
                    let fieldIndex = fieldIndex + decTy.NumInheritedInstanceFields

                    // OK now we need to store the field
                    let fieldPtr = LGC.buildStructGEP bldr selfPtr.Value (uint32 fieldIndex) (fieldRef.Name + "Ptr")
                    LGC.buildStore bldr (value.AsTypeReference(assemGen, fieldRef.FieldType)) fieldPtr |> ignore
                    goNext stackTail
                | _ ->
                    unexpPop()

            | Inst.Ldstr _ -> noImpl ()
            | Inst.Isinst _ -> noImpl ()
            | Inst.Castclass _ -> noImpl ()
            | Inst.Ldtoken tokProvider ->
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
                            let fieldIDVal = LGC.constInt (llvmIntTypeSized nativeIntSize) fieldID false
                            let fieldIDStackItem = new StackItem(bldr, fieldIDVal, StackType.NativeInt_ST, None)
                            let objStackItem = makeNewObj bldr md [fieldIDStackItem]
                            goNextStackItem objStackItem
                        | None -> failwith "failed to find constructor for runtime field handle"

                | _ ->
                    failwithf "no code to deal with tokProvider of type %s" (tokProvider.GetType().FullName)
                failwith "load tok"
            | Inst.Ldvirtftn _ -> noImpl ()

            // Value type instructions
            | Inst.Cpobj _ -> noImpl ()
            | Inst.Initobj _ -> noImpl ()
            | Inst.Ldobj (_unalignedPrefix, volatilePrefix, tyRef) ->
                // TODO deal with unaligned
                match poppedStack with
                | [src] ->
                    // TODO FIXME leaking memory here also this impl is probably wrong for many types
                    let cpTy = TypeUtil.LLVMNewableTypeOf assemGen tyRef
                    let dest = LGC.buildMalloc bldr cpTy "ldobj_copy_dest"
                    // TODO does this take care of volatile requirement?
                    LE.buildCopy moduleRef bldr dest (src.AsTypeReference(assemGen, tyRef)) volatilePrefix
                    let castTy = LGC.pointerType cpTy 0u
                    let destCast = LGC.buildBitCast bldr dest castTy "ldobj_copy_dest_cast"
                    // TODO is this load always right?? it seems strange but it works for now
                    let destLoad = LGC.buildLoad bldr destCast "ldobj_load_dest"
                    goNextValRef destLoad (Some tyRef)
                | _ ->
                    unexpPop()

            | Inst.Stobj (_unalignedPrefix, volatilePrefix, tyRef) ->
                // TODO deal with unaligned
                match poppedStack with
                | [src; dest] ->
                    if tyRef.IsPrimitive then
                        // TODO volatile?
                        let srcPrim = src.AsTypeReference(assemGen, tyRef)
                        let destPtr = dest.AsPointerTo(assemGen, tyRef)
                        LGC.buildStore bldr srcPrim destPtr |> ignore
                    else
                        let srcVal = src.AsTypeReference(assemGen, tyRef)
                        // TODO does this take care of volatile requirement?
                        LE.buildCopy moduleRef bldr dest.Value srcVal volatilePrefix
                    goNext stackTail
                | _ ->
                    unexpPop()
            | Inst.Box _ -> noImpl ()
            | Inst.Unbox _ -> noImpl ()
            | Inst.UnboxAny _ -> noImpl ()
            | Inst.Sizeof ty ->
                // TODO can sizeof param really be a typespec? Investigate this because if not,
                // this logic can be simplified
                let size =
                    match ty with
                    | :? FAP.TypeDefOrRef as ty ->
                        match ty.AsTypeBlob() with
                        | TyBlob.Boolean | TyBlob.U1 | TyBlob.U2 ->
                            1uL
                        | TyBlob.Char | TyBlob.U2 | TyBlob.I2 ->
                            2uL
                        | TyBlob.I4 | TyBlob.U4 | TyBlob.R4 ->
                            4uL
                        | TyBlob.I8 | TyBlob.U8 | TyBlob.R8 ->
                            8uL
                        | TyBlob.Ptr _ | TyBlob.I| TyBlob.U ->
                            uint64 nativeIntSize
                        (*
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
                        *)
                        | _ ->
                            noImpl()
                    | _ ->
                        failwithf "don't know how to do sizeof on a %s" (ty.GetType().Name)

                goNextValRef (LGC.constInt (LGC.int32Type()) size false) None

            // Generalized array instructions. In AbsIL these instructions include
            // both the single-dimensional variants (with ILArrayShape == ILArrayShape.SingleDimensional)
            // and calls to the "special" multi-dimensional "methods" such as
            //   newobj void string[,]::.ctor(int32, int32)
            //   call string string[,]::Get(int32, int32)
            //   call string& string[,]::Address(int32, int32)
            //   call void string[,]::Set(int32, int32,string)
            | Inst.Ldelem elemTyRef ->
                match poppedStack with
                | [index; arrObj] ->
                    let arrPtrAddr = LGC.buildStructGEP bldr arrObj.Value 1u "arrPtrAddr"
                    let arrPtr = LGC.buildLoad bldr arrPtrAddr "arrPtr"
                    // TODO: make sure that index.Value is good here... will work for all native ints or int32's
                    let elemAddr = LC.buildGEP bldr arrPtr [|index.Value|] "elemAddr"
                    let elem = LGC.buildLoad bldr elemAddr "elem"

                    goNextStackItem (StackItem.StackItemFromAny(bldr, elem, elemTyRef))
                | _ ->
                    unexpPop()
            | Inst.Stelem elemTyRef ->
                match poppedStack with
                | [value; index; arrObj] ->
                    let arrPtrAddr = LGC.buildStructGEP bldr arrObj.Value 1u "arrPtrAddr"
                    let arrPtr = LGC.buildLoad bldr arrPtrAddr "arrPtr"
                    // TODO: make sure that index.Value is good here... will work for all native ints or int32's
                    let elemAddr = LC.buildGEP bldr arrPtr [|index.Value|] "elemAddr"
                    LGC.buildStore bldr (value.AsTypeReference(assemGen, elemTyRef)) elemAddr |> ignore

                    goNext stackTail
                | _ ->
                    unexpPop()
            | Inst.Ldelema _ -> noImpl ()
            | Inst.LdelemI1 -> noImpl ()
            | Inst.LdelemU1 -> noImpl ()
            | Inst.LdelemI2 -> noImpl ()
            | Inst.LdelemU2 -> noImpl ()
            | Inst.LdelemI4 -> noImpl ()
            | Inst.LdelemU4 -> noImpl ()
            | Inst.LdelemI8 -> noImpl ()
            | Inst.LdelemI -> noImpl ()
            | Inst.LdelemR4 -> noImpl ()
            | Inst.LdelemR8 -> noImpl ()
            | Inst.LdelemRef -> noImpl ()
            | Inst.StelemI -> noImpl ()
            | Inst.StelemI1 -> noImpl ()
            | Inst.StelemI2 -> noImpl ()
            | Inst.StelemI4 -> noImpl ()
            | Inst.StelemI8 -> noImpl ()
            | Inst.StelemR4 -> noImpl ()
            | Inst.StelemR8 -> noImpl ()
            | Inst.StelemRef -> noImpl ()
            | Inst.Newarr elemTy ->
                match poppedStack with
                | [numElems] ->
                    // allocate the array to the heap
                    // TODO it seems pretty lame to have this code here. need to think
                    // about how this should really be structured
                    let llvmElemTy = TypeUtil.LLVMVarTypeOf assemGen elemTy
                    // TODO: make sure that numElems.Value is good here... will work for all native ints or int32's
                    let newArr = LGC.buildArrayMalloc bldr llvmElemTy numElems.Value ("new" + elemTy.Name + "Arr")

                    // TODO I think we have to initialize the arrays

                    let basicArrTy = LGC.pointerType llvmElemTy 0u
                    // FIXME array len should correspond to "native unsigned int" not int32
                    let arrObjTy = LC.structType [|LGC.int32Type (); basicArrTy|] false
                    let newArrObj = LGC.buildMalloc bldr arrObjTy ("new" + elemTy.Name + "ArrObj")

                    // fill in the array object
                    let lenAddr = LGC.buildStructGEP bldr newArrObj 0u "lenAddr"
                    // TODO: make sure that numElems.Value is good here... will work for all native ints or int32's
                    LGC.buildStore bldr numElems.Value lenAddr |> ignore
                    let arrPtrAddr = LGC.buildStructGEP bldr newArrObj 1u "arrPtrAddr"
                    LGC.buildStore bldr newArr arrPtrAddr |> ignore

                    // TODO "None" may be the wrong thing to do here
                    goNextValRef newArrObj None
                | _ ->
                    unexpPop()
            | Inst.Ldlen ->
                match poppedStack with
                | [arrObj] ->
                    let lenAddr = LGC.buildStructGEP bldr arrObj.Value 0u "lenAddr"
                    goNextValRef (LGC.buildLoad bldr lenAddr "len") None
                | _ ->
                    unexpPop()

            // "System.TypedReference" related instructions: almost
            // no languages produce these, though they do occur in mscorlib.dll
            // System.TypedReference represents a pair of a type and a byref-pointer
            // to a value of that type. 
            | Inst.Mkrefany _ -> noImpl ()
            | Inst.Refanytype -> noImpl ()
            | Inst.Refanyval _ -> noImpl ()
        
            // Debug-specific 
            | Inst.Break -> noImpl ()

            // Varargs - C++ only
            | Inst.Arglist -> noImpl ()

            // Local aggregates, i.e. stack allocated data (alloca) : C++ only
            | Inst.Localloc -> noImpl ()
            | Inst.Cpblk _ -> noImpl ()
            | Inst.Initblk _ -> noImpl ()

    let genLocal (bldr : LGC.BuilderRef) (l : FAP.LocalVarSig) =
        match l with
        | FAP.LocalVarSig.TypedByRef ->
            failwith "TODO vars typed by ref not yet supported"
        | FAP.LocalVarSig.SpecifiedType specTy ->
            if specTy.custMods.Length <> 0 then
                failwith "no support yet for non-empty cust mods in locals"
            if specTy.pinned then
                failwith "no support yet for pinned locals"
            match specTy.mayByRefType with
            | {FAP.MaybeByRefType.isByRef = false; ty = ty} ->
                let llvmTy = TypeUtil.LLVMVarTypeOfTypeBlob assemGen ty
                LGC.buildAlloca bldr llvmTy "localAlloca"
            | _ ->
                failwith "no support yet for byRef locals"

    let genParam (bldr : LGC.BuilderRef) (p : FAP.Parameter) =
        let llvmTy = TypeUtil.LLVMVarTypeOfParam assemGen p.Type
        LGC.buildAlloca bldr llvmTy "paramAlloca"

    let maybeGenMethodBody (methodVal : LGC.ValueRef) =

        //printfn "genMethodBody for: %s" methDef.FullName

        match methDef.MethodBody with
        | None -> ()
        | Some methBody ->
            // create the entry block
            use bldr = new LC.Builder(LGC.appendBasicBlock methodVal "entry")
            let args = Array.map (genParam bldr) methDef.AllParameters
            for i = 0 to args.Length - 1 do
                LGC.buildStore bldr (LGC.getParam methodVal (uint32 i)) args.[i] |> ignore
            let locals = Array.map (genLocal bldr) methBody.locals
            let blocks = methBody.blocks
            if blocks.Length = 0 then
                failwithf "empty method body: %s" methDef.Name
            let blockDecs = [|
                for i in 0 .. blocks.Length - 1 ->
                    LGC.appendBasicBlock methodVal (sprintf "block_%i" i)
            |]
            
            LGC.buildBr bldr blockDecs.[0] |> ignore
            for i in 0 .. blocks.Length - 1 do
                use bldr = new LC.Builder(blockDecs.[i])
                let insts = [for inst, _ in blocks.[i] -> inst]
                genInstructions
                    bldr
                    methodVal
                    args
                    locals
                    blockDecs
                    methDef
                    i
                    insts
                    []
            
            (*let blockDecs =
                [for b in blocks do
                    let blockName = "block_" + string b.OffsetBytes
                    yield (b.OffsetBytes, LGC.appendBasicBlock methodVal blockName)]
            match blockDecs with
            | [] -> failwith ("empty method body: " + methDef.FullName)
            | (_, fstBlockDec) :: _ ->
                LGC.buildBr bldr fstBlockDec |> ignore
                let blockMap = Map.ofList blockDecs
                for i in 0 .. blocks.Length - 1 do
                    if not blocks.[i].InitStackTypes.IsEmpty then
                        failwith "don't yet know how to deal with non empty basic blocks!!"
                    use bldr = new LC.Builder(blockMap.[blocks.[i].OffsetBytes])
                    genInstructions
                        bldr
                        methodVal
                        args
                        locals
                        blockMap
                        blocks.[i]
                        []
                        blocks.[i].Instructions*)

    let declareMethodDef () =

        let nameFunParam (fn : LGC.ValueRef) (i : int) (p : FAP.Parameter) =
            let llvmParam = LGC.getParam fn (uint32 i)
            let name = nameOrDefault p.Name ("arg" + string i)
            LGC.setValueName llvmParam name

        match methDef.MethodBody with
        | Some methBody ->
            let paramTys = [|for p in methDef.AllParameters -> TypeUtil.LLVMVarTypeOfParam assemGen p.Type|]
            let retTy = TypeUtil.LLVMVarTypeOfRetType assemGen methDef.ReturnType
            let funcTy = LC.functionType retTy paramTys
            let fnName = if methDef.Name = "main" then "_main" else methDef.Name
            let fn = LGC.addFunction moduleRef fnName funcTy
        
            Array.iteri (nameFunParam fn) methDef.AllParameters
        
            fn
        | None ->
            match methDef.PInvokeInfo with
            | Some pInv ->
                // TODO for now assuming that we don't need to use "dlopen"
                let modRef = pInv.ModuleRef
                if modRef.Name <> "libc.dll" then
                    failwithf "sorry! only works with libc for now. No dlopen etc.: %s" modRef.Name

                let paramTys = [|for p in methDef.Parameters -> TypeUtil.LLVMVarTypeOfParam assemGen p.Type|]
                let retTy = TypeUtil.LLVMVarTypeOfRetType assemGen methDef.ReturnType
                let funcTy = LC.functionType retTy paramTys
                let fn = LGC.addFunction moduleRef pInv.ImportName funcTy
                LGC.setLinkage fn LGC.Linkage.ExternalLinkage

                Seq.iteri (nameFunParam fn) methDef.Parameters

                fn
            | None ->
                failwith "don't know how to declare method without a body"

    let valueRef = {
        new DefAndImpl<LGC.ValueRef>() with
            member x.Define() = declareMethodDef ()
            member x.Implement vr = maybeGenMethodBody vr
    }

    member x.ValueRef = valueRef.Value

let genMainFunction
        (assemGen : AssemGen)
        (methDef : FAP.MethodDef)
        (llvmModuleRef : LGC.ModuleRef) =

    let argcTy = LGC.int32Type ()
    let argvTy = LGC.pointerType (LGC.pointerType (LGC.int8Type ()) 0u) 0u
    let cMainFnTy = LC.functionType (LGC.int32Type ()) [|argcTy; argvTy|]
    let cMainFn = LGC.addFunction llvmModuleRef "main" cMainFnTy
    LGC.setValueName (LGC.getParam cMainFn 0u) "argc"
    LGC.setValueName (LGC.getParam cMainFn 0u) "argv"

    use bldr = new LC.Builder(LGC.appendBasicBlock cMainFn "entry")
    let callResult =
        let resultName = if methDef.ReturnType.IsVoid then "" else "result"
        match methDef.Signature.methParams with
        | [] ->
            let valRef = assemGen.ClassMap.[methDef].MethodMap.[methDef].ValueRef
            LC.buildCall bldr valRef [||] resultName
        | [cmdLineArgs] ->
            //let safeParamTy = toSaferType cmdLineArgs.ParameterType
            let badType () =
                failwithf "main function should take no arguments or String[] but instead found %A" cmdLineArgs
            //match safeParamTy with
            match cmdLineArgs.pType with
            | FAP.ParamType.MayByRefTy cmdLineArgsTy ->
                match cmdLineArgsTy.ty with
                | FAP.TypeBlob.Array (FAP.TypeBlob.String, _arrShape) ->
                    // TODO build args string array
                    //buildCall bldr funMap.[cilMainMeth.FullName] [||] "result"
                    failwith "main taking string array not yet implemented"
                | _ -> badType ()
            | _ -> badType ()
        | ps -> failwithf "expected main method to have zero or one argument but found %i arguments" ps.Length

    match methDef.ReturnType.rType with
    | FAP.RetTypeKind.Void -> LGC.buildRet bldr (LGC.constInt (LGC.int32Type ()) 0uL false) |> ignore
    | FAP.RetTypeKind.MayByRefTy mayByRefTy ->
        match mayByRefTy.ty with
        | FAP.TypeBlob.I4 -> LGC.buildRet bldr callResult |> ignore
        | ty -> failwith "don't know how to deal with main return type of %A" ty
    | retTy -> failwith "don't know how to deal with main return type of %A" retTy

let genTypeDefs (llvmModuleRef : LGC.ModuleRef) (assem : FAP.Assembly) =

    let assemGen = new AssemGen(llvmModuleRef, assem)

    // force evaluation of all module types
    let rec goTypeDef (td : FAP.TypeDef) =
        let classRep = assemGen.ClassMap.[td]
        for m in td.Methods do
            classRep.MethodMap.[m].ValueRef |> ignore
        Seq.iter goTypeDef td.NestedTypes
    for m in assem.Modules do Seq.iter goTypeDef m.TypeDefs

    match assem.EntryPoint with
    | None -> ()
    | Some methDef -> genMainFunction assemGen methDef llvmModuleRef
