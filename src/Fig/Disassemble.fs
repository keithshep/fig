module Fig.Disassemble

open Fig.AssemblyParser
open Fig.IOUtil

open System.IO
open System.Text

let private labelAt addr = sprintf "IL_%04x" addr

let private rvaNameAt (rva : uint32) = sprintf "D_%08x" rva

let private bytesToString (bytes : byte array) =
    spaceSepStrs <| Array.map (sprintf "%02X") bytes

let private chunkSeq (s : #seq<_>) (chunkSize : int) =
    use e = s.GetEnumerator()
    [|
        while e.MoveNext() do
            yield [|
                yield e.Current
                let i = ref 1
                while !i < chunkSize && e.MoveNext() do
                    yield e.Current
                    i := !i + 1
            |]
    |]

let versionString (assemRef : AssemblyRef) =
    string assemRef.MajorVersion + ":" +
    string assemRef.MinorVersion + ":" +
    string assemRef.RevisionNumber + ":" +
    string assemRef.BuildNumber

let asStringLitteral (s : string) =
    let s = s.Replace(@"\", @"\\")
    let s = s.Replace("\n", @"\n")
    let s = s.Replace("\b", @"\b")
    let s = s.Replace("\r", @"\r")
    let s = s.Replace("\t", @"\t")
    let s = s.Replace("\"", "\\\"")

    "\"" + s + "\""

let disInst
        (tw : TextWriter)
        (indent : uint32)
        (assemCtxt : Assembly)
        (blockLabels : string array)
        (addr : uint32)
        (inst : AbstInst) =

    let lbl = labelAt addr
    let pr (s : string) = ifprintfn tw indent "%s: %s" lbl s

    let prMeth (instStr : string) (thisTyConst : TypeDefRefOrSpec option) (isTail : bool) (meth : Method) =
        let instStr =
            spaceSepStrs [|
                match thisTyConst with
                | None -> ()
                | Some ty ->
                    yield ".constrained"
                    yield ty.CilId(true, assemCtxt)

                if isTail then yield ".tail"

                yield instStr

                // TODO change the following to call.Method.Resolve
                yield meth.CilId(assemCtxt)
            |]
        pr instStr

    let maybePrependUnalignedVolatile (unalignedOpt : byte option) (isVolatile : bool) (s : string) =
        let s =
            match unalignedOpt with
            | None -> s
            | Some unaligned -> "unaligned. " + string unaligned + " " + s
        if isVolatile then
            "volatile. " + s
        else
            s

    let maybePrependVolatile (vol:bool) (s:string) =
        maybePrependUnalignedVolatile None vol s

    match inst with
    | AbstInst.Add -> "add" |> pr
    | AbstInst.And -> "and" |> pr
    | AbstInst.Beq tgt -> "beq " + blockLabels.[tgt] |> pr
    | AbstInst.Bge tgt -> "bge " + blockLabels.[tgt] |> pr
    | AbstInst.Bgt tgt -> "bgt " + blockLabels.[tgt] |> pr
    | AbstInst.Ble tgt -> "ble " + blockLabels.[tgt] |> pr
    | AbstInst.Blt tgt -> "blt " + blockLabels.[tgt] |> pr
    | AbstInst.BneUn tgt -> "bne.un " + blockLabels.[tgt] |> pr
    | AbstInst.BgeUn tgt -> "bge.un " + blockLabels.[tgt] |> pr
    | AbstInst.BgtUn tgt -> "bgt.un " + blockLabels.[tgt] |> pr
    | AbstInst.BleUn tgt -> "ble.un " + blockLabels.[tgt] |> pr
    | AbstInst.BltUn tgt -> "blt.un " + blockLabels.[tgt] |> pr
    | AbstInst.Br tgt -> "br " + blockLabels.[tgt] |> pr
    | AbstInst.Break -> "break" |> pr
    | AbstInst.Brfalse tgt -> "brfalse " + blockLabels.[tgt] |> pr
    | AbstInst.Brtrue tgt -> "brtrue " + blockLabels.[tgt] |> pr
    | AbstInst.Call call -> prMeth "call" None call.Tail call.Method
    | AbstInst.Calli call -> prMeth "calli" None call.Tail call.Method
    | AbstInst.Callvirt virtcall -> prMeth "callvirt" virtcall.ThisType virtcall.Tail virtcall.Method
    | AbstInst.ConvI1 -> "conv.i1" |> pr
    | AbstInst.ConvI2 -> "conv.i2" |> pr
    | AbstInst.ConvI4 -> "conv.i4" |> pr
    | AbstInst.ConvI8 -> "conv.i8" |> pr
    | AbstInst.ConvR4 -> "conv.r4" |> pr
    | AbstInst.ConvR8 -> "conv.r8" |> pr
    | AbstInst.ConvU4 -> "conv.u4" |> pr
    | AbstInst.ConvU8 -> "conv.u8" |> pr
    | AbstInst.Cpobj ty -> "cpobj " + ty.CilId(true, assemCtxt) |> pr
    | AbstInst.Div -> "div" |> pr
    | AbstInst.DivUn -> "div.un" |> pr
    | AbstInst.Dup -> "dup" |> pr
    (*
    | AbstInst.Jmp of MetadataToken
    *)
    | AbstInst.Ldarg i -> "ldarg " + string i |> pr
    | AbstInst.Ldarga i -> "ldarga " + string i |> pr
    | AbstInst.LdcI4 i -> "ldc.i4 " + string i |> pr
    | AbstInst.LdcI8 i -> "ldc.i8 " + string i |> pr
    | AbstInst.LdcR4 r -> "ldc.r4 " + string r |> pr
    | AbstInst.LdcR8 r -> "ldc.r8 " + string r |> pr
    | AbstInst.LdindU1 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.u1" |> pr
    | AbstInst.LdindI2 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.i2" |> pr
    | AbstInst.LdindU2 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.u2" |> pr
    | AbstInst.LdindI4 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.i4" |> pr
    | AbstInst.LdindU4 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.u4" |> pr
    | AbstInst.LdindI8 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.i8" |> pr
    | AbstInst.LdindI (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.i" |> pr
    | AbstInst.LdindR4 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.r4" |> pr
    | AbstInst.LdindR8 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.r8" |> pr
    | AbstInst.LdindRef (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.ref" |> pr
    | AbstInst.Ldloc i -> "ldloc " + string i |> pr
    | AbstInst.Ldloca i -> "ldloca " + string i |> pr
    | AbstInst.Ldnull -> "ldnull" |> pr
    | AbstInst.Ldobj (alignOpt, vol, ty) ->
        let instStr = "ldobj " + ty.CilId(false, assemCtxt)
        maybePrependUnalignedVolatile alignOpt vol instStr |> pr
    | AbstInst.Ldstr s -> "ldstr " + asStringLitteral s |> pr
    | AbstInst.Mul -> "mul" |> pr
    | AbstInst.Neg -> "neg" |> pr
    | AbstInst.Nop -> "nop" |> pr
    | AbstInst.Not -> "not" |> pr
    | AbstInst.Newobj meth -> prMeth "newobj" None false meth
    | AbstInst.Or -> "or" |> pr
    | AbstInst.Pop -> "pop" |> pr
    | AbstInst.Rem -> "rem" |> pr
    | AbstInst.RemUn -> "rem.un" |> pr
    | AbstInst.Ret -> "ret" |> pr
    | AbstInst.Shl -> "shl" |> pr
    | AbstInst.Shr -> "shr" |> pr
    | AbstInst.ShrUn -> "shr.un" |> pr
    | AbstInst.Starg i -> "starg " + string i |> pr
    | AbstInst.StindRef (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "stind.ref" |> pr
    | AbstInst.StindI1 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "stind.i1" |> pr
    | AbstInst.StindI2 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "stind.i2" |> pr
    | AbstInst.StindI4 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "stind.i4" |> pr
    | AbstInst.StindI8 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "stind.i8" |> pr
    | AbstInst.StindR4 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "stind.r4" |> pr
    | AbstInst.StindR8 (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "stind.r8" |> pr
    | AbstInst.Stloc i -> "stloc " + string i |> pr
    | AbstInst.Sub -> "sub" |> pr
    | AbstInst.Switch tgts ->
        pr "switch ("
        for i = 0 to tgts.Length - 2 do
            ifprintfn tw (indent + 1u) "%s," blockLabels.[tgts.[i]]
        ifprintfn tw (indent + 1u) "%s)" blockLabels.[tgts.[tgts.Length - 1]]
    | AbstInst.Xor -> "xor" |> pr
    | AbstInst.Castclass ty -> "castclass " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.Isinst ty -> "isinst " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.ConvRUn -> "conv.r.un" |> pr
    | AbstInst.Unbox ty -> "unbox " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.Throw -> "throw" |> pr
    | AbstInst.Ldfld (alignOpt, vol, fld) ->
        maybePrependUnalignedVolatile alignOpt vol ("ldfld " + fld.CilId(assemCtxt)) |> pr
    | AbstInst.Ldflda (alignOpt, vol, fld) ->
        maybePrependUnalignedVolatile alignOpt vol ("ldflda " + fld.CilId(assemCtxt)) |> pr
    | AbstInst.Stfld (alignOpt, vol, fld) ->
        maybePrependUnalignedVolatile alignOpt vol ("stfld " + fld.CilId(assemCtxt)) |> pr
    | AbstInst.Ldsfld (vol, fld) ->
        let instStr = "ldsfld " + fld.CilId(assemCtxt)
        maybePrependVolatile vol instStr |> pr
    | AbstInst.Ldsflda (vol, fld) ->
        let instStr = "ldsflda " + fld.CilId(assemCtxt)
        maybePrependVolatile vol instStr |> pr
    | AbstInst.Stsfld (vol, fld) ->
        let instStr = "stsfld " + fld.CilId(assemCtxt)
        maybePrependVolatile vol instStr |> pr
    | AbstInst.Stobj (alignOpt, vol, ty) ->
        let instStr = "stobj " + ty.CilId(false, assemCtxt)
        maybePrependUnalignedVolatile alignOpt vol instStr |> pr
    | AbstInst.ConvOvfI1Un -> "conv.ovf.i1.un" |> pr
    | AbstInst.ConvOvfI2Un -> "conv.ovf.i2.un" |> pr
    | AbstInst.ConvOvfI4Un -> "conv.ovf.i4.un" |> pr
    | AbstInst.ConvOvfI8Un -> "conv.ovf.i8.un" |> pr
    | AbstInst.ConvOvfU1Un -> "conv.ovf.u1.un" |> pr
    | AbstInst.ConvOvfU2Un -> "conv.ovf.u2.un" |> pr
    | AbstInst.ConvOvfU4Un -> "conv.ovf.u4.un" |> pr
    | AbstInst.ConvOvfU8Un -> "conv.ovf.u8.un" |> pr
    | AbstInst.ConvOvfIUn -> "conv.ovf.i.un" |> pr
    | AbstInst.ConvOvfUUn -> "conv.ovf.u.un" |> pr
    | AbstInst.Box ty -> "box " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.Newarr ty -> "newarr " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.Ldlen -> "ldlen" |> pr
    | AbstInst.Ldelema ty -> "ldelema " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.LdelemI1 -> "ldelem.i1" |> pr
    | AbstInst.LdelemU1 -> "ldelem.u1" |> pr
    | AbstInst.LdelemI2 -> "ldelem.i2" |> pr
    | AbstInst.LdelemU2 -> "ldelem.u2" |> pr
    | AbstInst.LdelemI4 -> "ldelem.i4" |> pr
    | AbstInst.LdelemU4 -> "ldelem.u4" |> pr
    | AbstInst.LdelemI8 -> "ldelem.i8" |> pr
    | AbstInst.LdelemI -> "ldelem.i" |> pr
    | AbstInst.LdelemR4 -> "ldelem.r4" |> pr
    | AbstInst.LdelemR8 -> "ldelem.r8" |> pr
    | AbstInst.LdelemRef -> "ldelem.ref" |> pr
    | AbstInst.StelemI -> "stelem.i" |> pr
    | AbstInst.StelemI1 -> "stelem.i1" |> pr
    | AbstInst.StelemI2 -> "stelem.i2" |> pr
    | AbstInst.StelemI4 -> "stelem.i4" |> pr
    | AbstInst.StelemI8 -> "stelem.i8" |> pr
    | AbstInst.StelemR4 -> "stelem.r4" |> pr
    | AbstInst.StelemR8 -> "stelem.r8" |> pr
    | AbstInst.StelemRef -> "stelem.ref" |> pr
    | AbstInst.Ldelem ty -> "ldelem " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.Stelem ty -> "stelem " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.UnboxAny ty -> "unbox.any " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.ConvOvfI1 -> "conv.ovf.i1" |> pr
    | AbstInst.ConvOvfU1 -> "conv.ovf.u1" |> pr
    | AbstInst.ConvOvfI2 -> "conv.ovf.i2" |> pr
    | AbstInst.ConvOvfU2 -> "conv.ovf.u2" |> pr
    | AbstInst.ConvOvfI4 -> "conv.ovf.i4" |> pr
    | AbstInst.ConvOvfU4 -> "conv.ovf.u4" |> pr
    | AbstInst.ConvOvfI8 -> "conv.ovf.i8" |> pr
    | AbstInst.ConvOvfU8 -> "conv.ovf.u8" |> pr
    (*
    | AbstInst.Refanyval of MetadataToken
    *)
    | AbstInst.Ckfinite -> "ckfinite" |> pr
    (*
    | AbstInst.Mkrefany of MetadataToken
    | AbstInst.Ldtoken of MetadataToken
    *)
    | AbstInst.ConvU2 -> "conv.u2" |> pr
    | AbstInst.ConvU1 -> "conv.u1" |> pr
    | AbstInst.ConvI -> "conv.i" |> pr
    | AbstInst.ConvOvfI -> "conv.ovf.i" |> pr
    | AbstInst.ConvOvfU -> "conv.ovf.u" |> pr
    | AbstInst.AddOvf -> "add.ovf" |> pr
    | AbstInst.AddOvfUn -> "add.ovf.un" |> pr
    | AbstInst.MulOvf -> "mul.ovf" |> pr
    | AbstInst.MulOvfUn -> "mul.ovf.un" |> pr
    | AbstInst.SubOvf -> "sub.ovf" |> pr
    | AbstInst.SubOvfUn -> "sub.ovf.un" |> pr
    | AbstInst.Endfinally -> "endfinally" |> pr
    | AbstInst.Leave tgt -> "leave " + blockLabels.[tgt] |> pr
    | AbstInst.StindI (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "ldind.i" |> pr
    | AbstInst.ConvU -> "conv.u" |> pr
    | AbstInst.Arglist -> "arglist" |> pr
    | AbstInst.Ceq -> "ceq" |> pr
    | AbstInst.Cgt -> "cgt" |> pr
    | AbstInst.CgtUn -> "cgt.un" |> pr
    | AbstInst.Clt -> "clt" |> pr
    | AbstInst.CltUn -> "clt.un" |> pr
    | AbstInst.Ldftn meth -> prMeth "ldftn" None false meth
    //| AbstInst.Ldvirtftn of MetadataToken
    | AbstInst.Localloc -> "localloc" |> pr
    | AbstInst.Endfilter -> "endfilter" |> pr
    | AbstInst.Initobj ty -> "initobj " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.Cpblk vol -> maybePrependVolatile vol "cpblk" |> pr
    | AbstInst.Initblk (alignOpt, vol) -> maybePrependUnalignedVolatile alignOpt vol "initblk" |> pr
    | AbstInst.Rethrow -> "rethrow" |> pr
    | AbstInst.Sizeof ty -> "sizeof " + ty.CilId(false, assemCtxt) |> pr
    | AbstInst.Refanytype -> "refanytype" |> pr
    | _ ->
        //sprintf "TODO %A" inst |> pr
        "TODO" |> pr

let genConstrToStr (genConstr : TypeDefRefOrSpec) =
    // Partition II 10.1.7 Generic parameters (GenPars)

    // TODO I know this is wrong
    match genConstr with
    | :? TypeDefOrRef as genConstr -> genConstr.FullName
    | _ -> "YEAH_NO_CAN_DO"

let genParToStr (genPar : GenericParam) =
    // Partition II 10.1.7 Generic parameters (GenPars)
    spaceSepStrs [|
        match genPar.Variance with
        | GenericParamVariance.Covariant        -> yield "+"
        | GenericParamVariance.Contravariant    -> yield "-"
        | GenericParamVariance.None             -> () // no-op
        
        if genPar.ReferenceTypeConstrained          then yield "class"
        if genPar.NotNullableValueTypeConstrained   then yield "valuetype"
        if genPar.DefaultConstructorConstrained     then yield ".ctor"

        let genConstrs = Array.ofSeq genPar.Constraints
        if not <| Array.isEmpty genConstrs then
            yield "(" + commaSepStrs (Array.map genConstrToStr genConstrs) + ")"

        yield genPar.Name
    |]

let paramsToStr (assemCtxt : Assembly) (ps : Param list) =
    commaSepStrs [|
        for p in ps do
            // TODO deal with cust mods [INOUT] and all that junk
            yield p.pType.CilId(assemCtxt)
    |]

let disMethodDef (tw : TextWriter) (indent : uint32) (assemCtxt : Assembly) (md : MethodDef) =
    
    // .method MethodHeader '{' MethodBodyItem* '}'
    // MethAttr* [ CallConv ] Type [marshal '(' [NativeType] ')']
    //           MethodName [ '<' GenPars '>' ] '(' Parameters ')' ImplAttr*
    
    let methodHeader = [|
        yield ".method"

        // method attributes
        if md.IsAbstract then yield "abstract"
        
        yield md.MemberAccess.ToString()

        if md.HideBySig then yield "hidebysig"
        if md.NewVTableSlot then yield "newslot"

        // TODO PINVOKE JUNK HERE
        
        if md.RTSpecialName then yield "rtspecialname"
        if md.SpecialName then yield "specialname"
        if md.IsStatic then yield "static"
        if md.IsVirtual then yield "virtual"
        if md.IsStrict then yield "strict"

        // calling convention
        match md.Signature.thisKind with
        | ThisKind.NoThis -> ()
        | ThisKind.ExplicitThis -> yield! [|"instance"; "explicit"|]
        | ThisKind.HasThis -> yield "instance"

        let methSig = md.Signature
        // TODO CallKind's like "unmanaged cdecl" etc
        yield
            match methSig.callingConv with
            | MethCallingConv.Default | MethCallingConv.Generic _ ->
                // TODO are we supposed to yield "default" for generic
                "default"
            | MethCallingConv.Vararg ->
                "vararg"
        
        for cm in methSig.retType.customMods do
            yield cm.CilId(assemCtxt)

        yield md.Name
    |]

    ifprintfn tw indent "%s ()" (spaceSepStrs methodHeader)
    ifprintfn tw indent "{"
    
    match md.MethodBody with
    | None -> ()
    | Some mb ->
        let indent = indent + 1u
        ifprintfn tw indent ".maxstack %i" mb.maxStack

        if mb.locals.Length >= 1 then
            let localToStr (i : int) =
                match mb.locals.[i] with
                | LocalVarSig.TypedByRef -> failwith "TODO yeah how do I represent this"
                | LocalVarSig.SpecifiedType specLocalVar ->
                    if specLocalVar.custMods.Length >= 1 then
                        failwith "TODO yup custMods"
                    if specLocalVar.pinned then
                        failwith "TODO what do i do with a pinned local"
                    if specLocalVar.mayByRefType.isByRef then
                        failwith "TODO what do i do with this byref?"
                    let tyStr = specLocalVar.mayByRefType.ty.CilId(assemCtxt)
                    sprintf "%s V_%i" tyStr i

            if mb.initLocals then
                ifprintfn tw indent ".locals init ("
            else
                ifprintfn tw indent ".locals ("

            for i = 0 to mb.locals.Length - 2 do
                ifprintfn tw (indent + 1u) "%s," (localToStr i)
            ifprintfn tw (indent + 1u) "%s)" (localToStr (mb.locals.Length - 1))
        
        let currAddr = ref 0u
        let blockLabels = [|
            for block in mb.blocks do
                yield labelAt !currAddr
                for _, instSize in block do
                    currAddr := !currAddr + instSize
        |]

        let mutable currAddr = 0u
        for block in mb.blocks do
            for inst, instSize in block do
                disInst tw indent assemCtxt blockLabels currAddr inst
                currAddr <- currAddr + instSize

    ifprintfn tw indent "}"

let fieldToStr (assemCtxt : AssemblyBase) (field : FieldDef) =
    spaceSepStrs [|
        yield ".field"

        match field.Offset with
        | None -> ()
        | Some off -> yield "[" + string off + "]"

        yield field.MemberAccess.ToString()
        if field.SpecialName then yield "specialname"
        if field.RTSpecialName then yield "rtspecialname"
        if field.IsStatic then yield "static"
        if field.IsLiteral then yield "literal"
        if field.IsInitOnly then yield "initonly"
        yield field.Signature.CilId(assemCtxt)
        yield field.Name
        match field.ConstantValue with
        | None -> ()
        | Some constVal ->
            let noImpl() = failwithf "TODO add field type impl for %A" constVal.Type
            let invalTy() = failwithf "TODO invalid field type %A" constVal.Type
            yield "="

            // Type shall be exactly one of:
            // ELEMENT_TYPE_BOOLEAN, ELEMENT_TYPE_CHAR, ELEMENT_TYPE_I1, ELEMENT_TYPE_U1,
            // ELEMENT_TYPE_I2, ELEMENT_TYPE_U2, ELEMENT_TYPE_I4, ELEMENT_TYPE_U4,
            // ELEMENT_TYPE_I8, ELEMENT_TYPE_U8, ELEMENT_TYPE_R4, ELEMENT_TYPE_R8, or
            // ELEMENT_TYPE_STRING; or ELEMENT_TYPE_CLASS with a Value of zero
            let tyName =
                match constVal.Type with
                | ElementType.Boolean | ElementType.Char -> noImpl()
                | ElementType.I1 | ElementType.U1 -> "int8"
                | ElementType.I2 | ElementType.U2 -> "int16"
                | ElementType.I4 | ElementType.U4 -> "int32"
                | ElementType.I8 | ElementType.U8 -> "int64"
                | ElementType.R4 | ElementType.R8
                | ElementType.String | ElementType.Class -> noImpl()
                | _ -> invalTy()

            let valStr =
                match constVal.Type with
                | ElementType.Boolean | ElementType.Char -> noImpl()
                | ElementType.I1 | ElementType.U1 ->
                    sprintf "0x%02x" constVal.Value.[0]
                | ElementType.I2 | ElementType.U2 ->
                    sprintf "0x%08x" (System.BitConverter.ToInt16(constVal.Value, 0))
                | ElementType.I4 | ElementType.U4 ->
                    sprintf "0x%08x" (System.BitConverter.ToInt32(constVal.Value, 0))
                | ElementType.I8 | ElementType.U8 ->
                    sprintf "0x%016x" (System.BitConverter.ToInt64(constVal.Value, 0))
                | ElementType.R4 | ElementType.R8
                | ElementType.String | ElementType.Class -> noImpl()
                | _ -> invalTy()

            yield tyName + "(" + valStr + ")"

        match field.FieldRVA with
        | None -> ()
        | Some rva ->
            yield "at"
            yield rvaNameAt rva
    |]

let disProperty (tw : TextWriter) (ident : uint32) (assemCtxt : Assembly) (prop : Property) =
    let propSig = prop.Signature
    let propHeaderStr =
        spaceSepStrs [|
            yield ".property"
            yield if propSig.hasThis then "instance" else "class"
            yield propSig.propType.CilId(assemCtxt)
            yield prop.Name
            yield "(" + paramsToStr assemCtxt propSig.indexParams + ")"
        |]
    ifprintfn tw ident "%s" propHeaderStr
    ifprintfn tw ident "{"
    for methSem in prop.MethodSemantics do
        let methSemStr =
            spaceSepStrs [|
                yield
                    match methSem.PropKind with
                    | PropKind.Getter -> ".get"
                    | PropKind.Setter -> ".set"
                    | PropKind.Other -> ".other"
                let md = methSem.Method
                //if md.SpecialName then yield "specialname"
                //if md.RTSpecialName then yield "rtspecialname"
                match md.Signature.thisKind with
                | ThisKind.NoThis -> ()
                | ThisKind.ExplicitThis -> yield! [|"instance"; "explicit"|]
                | ThisKind.HasThis -> yield "instance"

                let methSig = md.Signature
                // TODO CallKind's like "unmanaged cdecl" etc
                yield
                    match methSig.callingConv with
                    | MethCallingConv.Default | MethCallingConv.Generic _ ->
                        // TODO are we supposed to yield "default" for generic
                        "default"
                    | MethCallingConv.Vararg ->
                        "vararg"
                yield md.Signature.retType.CilId(assemCtxt)
                yield md.DeclaringType.FullName + "::" + md.Name
                yield "(" + paramsToStr assemCtxt md.Signature.methParams + ")"
            |]
        ifprintfn tw (ident + 1u) "%s" methSemStr
    ifprintfn tw ident "}"

let rec disTypeDef (tw : TextWriter) (indent : uint32) (assemCtxt : Assembly) (td : TypeDef) =

    let dealWithTypePart (indent : uint32) =
        // partition II 10.1
        let classHeaderStrs = [|
            yield ".class"

            // ClassAttr* Id ['<' GenPars '>' ] [ extends TypeSpec [ implements TypeSpec ] [ ',' TypeSpec ]* ]

            // type attributes
            if td.IsAbstract then yield "abstract"

            yield
                match td.StringFormattingAttr with
                | StringFmtAttr.Ansi    -> "ansi"
                | StringFmtAttr.Auto    -> "autochar"
                | StringFmtAttr.Unicode -> "unicode"
                | StringFmtAttr.Custom  ->
                    failwith "don't know how to deal with custom string formats"

            yield
                match td.ClassLayoutAttr with
                | ClassLayoutAttr.Auto          -> "auto"
                | ClassLayoutAttr.Explicit      -> "explicit"
                | ClassLayoutAttr.Sequential    -> "sequential"
        
            if td.BeforeFieldInit then  yield "beforefieldinit"
            if td.IsInterface then      yield "interface"

            yield
                match td.TypeVisibilityAttr with
                | TypeVisibilityAttr.NestedAssembly     -> "nested assembly"
                | TypeVisibilityAttr.NestedFamANDAssem  -> "nested famandassem"
                | TypeVisibilityAttr.NestedFamily       -> "nested family"
                | TypeVisibilityAttr.NestedFamORAssem   -> "nested famorassem"
                | TypeVisibilityAttr.NestedPrivate      -> "nested private"
                | TypeVisibilityAttr.NestedPublic       -> "nested public"
                | TypeVisibilityAttr.NotPublic          -> "private"
                | TypeVisibilityAttr.Public             -> "public"

            if td.RTSpecialName then    yield "rtspecialname"
            if td.IsSealed then         yield "sealed"
            if td.IsSerializable then   yield "serializable"
            if td.IsSpecialName then    yield "specialname"

            // optional generic parameters
            let genPars = td.GenericParams |> Array.ofSeq
            if not <| Array.isEmpty genPars then
                let sb = new StringBuilder("<")

                let genParStr = commaSepStrs <| Array.map genParToStr genPars
                sb.Append genParStr |> ignore

                sb.Append '>' |> ignore

                yield sb.ToString()

            // name
            yield td.Name

            // base type
            match td.Extends with
            | None -> ()
            | Some (:? TypeDefOrRef as ty) ->
                yield "extends"

                // TODO need to add something along the lines of "[assembly name]" to this
                yield ty.FullName
            | Some _ ->
                yield "extends"
                yield "TODO_TYPE_SPEC"

            // an optional list of interfaces
            let imps = td.Implements
            if not (Array.isEmpty imps) then
                yield "implements"
                // TODO need to add something along the lines of "[assembly name]" to this
                yield commaSepStrs [|
                    for imp in imps ->
                        match imp with
                        | :? TypeDefOrRef as imp -> imp.FullName
                        | _ -> "TODO_IMPLEMENTS_TYPE_SPEC"
                |]
        |]

        ifprintfn tw indent "%s" (spaceSepStrs classHeaderStrs)
        ifprintfn tw indent "{"

        match td.ClassLayout with
        | None -> ()
        | Some cl ->
            ifprintfn tw (indent + 1u) ".pack %i" cl.packingSize
            ifprintfn tw (indent + 1u) ".size %i" cl.classSize

        for field in td.Fields do
            ifprintfn tw (indent + 1u) "%s" (fieldToStr assemCtxt field)

        Array.iter (disMethodDef tw (indent + 1u) assemCtxt) td.Methods
        Array.iter (disProperty tw (indent + 1u) assemCtxt) td.Properties
        Array.iter (disTypeDef tw (indent + 1u) assemCtxt) td.NestedTypes

        ifprintfn tw indent "}"
    
    match td.Namespace with
    | None -> dealWithTypePart indent
    | Some ns ->
        ifprintfn tw indent ".namespace %s" ns
        ifprintfn tw indent "{"
        dealWithTypePart (indent + 1u)
        ifprintfn tw indent "}"

let disModule (tr : TextWriter) (assem : Assembly) (m : Module) =
    fprintfn tr ".module %s" m.Name
    tr.WriteLine()

    for td in m.TypeDefs do
        disTypeDef tr 1u assem td

let disData (tw : TextWriter) (assem : Assembly) =
    for m in assem.Modules do
        for td in m.TypeDefs do
            for field in td.Fields do
                match field.Data with
                | None -> ()
                | Some data ->
                    let rva = Option.get field.FieldRVA
                    fprintfn tw ".data %s = bytearray (" (rvaNameAt rva)
                    let chunks = Array.ofSeq (chunkSeq data 16)
                    for i = 0 to chunks.Length - 2 do
                        let chunkStr = bytesToString (Array.ofSeq chunks.[i])
                        ifprintfn tw 1u "%s" chunkStr
                    if chunks.Length = 0 then
                        ifprintfn tw 1u ")"
                    else
                        let chunkStr = bytesToString (Array.ofSeq chunks.[chunks.Length - 1])
                        ifprintfn tw 1u "%s)" chunkStr

let disassemble (tw : TextWriter) (assem : Assembly) =
    for ar in assem.AssemblyRefs do
        fprintfn tw ".assembly extern %s" ar.Name
        fprintfn tw "{"
        ifprintfn tw 1u ".ver %s" (versionString ar)
        match ar.PublicKeyOrToken with
        | None -> ()
        | Some pubKeyOrTok ->
            if not ar.IsPublicKeySet then
                ifprintfn tw 1u ".publickeytoken = (%s)" (bytesToString pubKeyOrTok)
            else
                failwith "implement me dude"

        fprintfn tw "}"

    fprintfn tw ".assembly %s" assem.Name
    fprintfn tw "{"

    fprintfn tw "}"

    let modules = assem.Modules
    if modules.Length <> 1 then
        failwith "TODO deal with multi module assemblies"
    for m in modules do disModule tw assem m

    disData tw assem
