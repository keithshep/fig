module Fig.Disassemble

open Fig.AssemblyParser
open Fig.IOUtil

open System.IO
open System.Text

let private labelAt addr = sprintf "IL_%04x" addr

let private sepStrsWith (sep : string) (strings : string array) =
    if Array.isEmpty strings then
        ""
    else
        let sb = new StringBuilder()
        sb.Append strings.[0] |> ignore
        for i in 1 .. strings.Length - 1 do
            sb.Append sep |> ignore
            sb.Append strings.[i] |> ignore
        sb.ToString()
let private spaceSepStrs = sepStrsWith " "
let private commaSepStrs = sepStrsWith ", "

let private bytesToString (bytes : byte array) =
    spaceSepStrs <| Array.map (sprintf "%02X") bytes

let versionString (assemRef : AssemblyRef) =
    string assemRef.MajorVersion + ":" +
    string assemRef.MinorVersion + ":" +
    string assemRef.RevisionNumber + ":" +
    string assemRef.BuildNumber

let disInst
        (tw : TextWriter)
        (indent : uint32)
        (blockLabels : string array)
        (addr : uint32)
        (inst : AbstInst) =

    let lbl = labelAt addr
    let pr (s : string) = ifprintfn tw indent "%s: %s" lbl s

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
    (*
    | AbstInst.Call of bool * MetadataToken
    | AbstInst.Calli of bool * MetadataToken
    | AbstInst.Callvirt of MetadataToken option * bool * MetadataToken
    *)
    | AbstInst.ConvI1 -> "conv.i1" |> pr
    | AbstInst.ConvI2 -> "conv.i2" |> pr
    | AbstInst.ConvI4 -> "conv.i4" |> pr
    | AbstInst.ConvI8 -> "conv.i8" |> pr
    | AbstInst.ConvR4 -> "conv.r4" |> pr
    | AbstInst.ConvR8 -> "conv.r8" |> pr
    | AbstInst.ConvU4 -> "conv.u4" |> pr
    | AbstInst.ConvU8 -> "conv.u8" |> pr
    (*
    | AbstInst.Cpobj of MetadataToken
    *)
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
    (*
    | AbstInst.LdindU1 of byte option
    | AbstInst.LdindI2 of byte option
    | AbstInst.LdindU2 of byte option
    | AbstInst.LdindI4 of byte option
    | AbstInst.LdindU4 of byte option
    | AbstInst.LdindI8 of byte option
    | AbstInst.LdindI of byte option
    | AbstInst.LdindR4 of byte option
    | AbstInst.LdindR8 of byte option
    | AbstInst.LdindRef of byte option
    *)
    | AbstInst.Ldloc i -> "ldloc " + string i |> pr
    | AbstInst.Ldloca i -> "ldloca " + string i |> pr
    | AbstInst.Ldnull -> "ldnull" |> pr
    (*
    | AbstInst.Ldobj of byte option * MetadataToken
    | AbstInst.Ldstr of MetadataToken
    *)
    | AbstInst.Mul -> "mul" |> pr
    | AbstInst.Neg -> "neg" |> pr
    | AbstInst.Nop -> "nop" |> pr
    | AbstInst.Not -> "not" |> pr
    (*
    | AbstInst.Newobj of MetadataToken
    *)
    | AbstInst.Or -> "or" |> pr
    | AbstInst.Pop -> "pop" |> pr
    | AbstInst.Rem -> "rem" |> pr
    | AbstInst.RemUn -> "rem.un" |> pr
    | AbstInst.Ret -> "ret" |> pr
    | AbstInst.Shl -> "shl" |> pr
    | AbstInst.Shr -> "shr" |> pr
    | AbstInst.ShrUn -> "shr.un" |> pr
    | AbstInst.Starg i -> "starg " + string i |> pr
    (*
    | AbstInst.StindRef of byte option
    | AbstInst.StindI1 of byte option
    | AbstInst.StindI2 of byte option
    | AbstInst.StindI4 of byte option
    | AbstInst.StindI8 of byte option
    | AbstInst.StindR4 of byte option
    | AbstInst.StindR8 of byte option
    *)
    | AbstInst.Stloc i -> "stloc " + string i |> pr
    | AbstInst.Sub -> "sub" |> pr
    | AbstInst.Switch tgts ->
        pr "switch ("
        for i = 0 to tgts.Length - 2 do
            ifprintfn tw (indent + 1u) "%s," blockLabels.[tgts.[i]]
        ifprintfn tw (indent + 1u) "%s)" blockLabels.[tgts.[tgts.Length - 1]]
    | AbstInst.Xor -> "xor" |> pr
    (*
    | AbstInst.Castclass of MetadataToken
    | AbstInst.Isinst of MetadataToken
    *)
    | AbstInst.ConvRUn -> "conv.r.un" |> pr
    (*
    | AbstInst.Unbox of MetadataToken
    *)
    | AbstInst.Throw -> "throw" |> pr
    (*
    | AbstInst.Ldfld of byte option * MetadataToken
    | AbstInst.Ldflda of byte option * MetadataToken
    | AbstInst.Stfld of byte option * MetadataToken
    | AbstInst.Ldsfld of MetadataToken
    | AbstInst.Ldsflda of MetadataToken
    | AbstInst.Stsfld of MetadataToken
    | AbstInst.Stobj of byte option * MetadataToken
    *)
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
    (*
    | AbstInst.Box of MetadataToken
    | AbstInst.Newarr of MetadataToken
    *)
    | AbstInst.Ldlen -> "ldlen" |> pr
    (*
    | AbstInst.Ldelema of MetadataToken
    *)
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
    (*
    | AbstInst.Ldelem of MetadataToken
    | AbstInst.Stelem of MetadataToken
    | AbstInst.UnboxAny of MetadataToken
    *)
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
    //| AbstInst.Leave of int
    //| AbstInst.StindI of byte option
    | AbstInst.ConvU -> "conv.u" |> pr
    | AbstInst.Arglist -> "arglist" |> pr
    | AbstInst.Ceq -> "ceq" |> pr
    | AbstInst.Cgt -> "cgt" |> pr
    | AbstInst.CgtUn -> "cgt.un" |> pr
    | AbstInst.Clt -> "clt" |> pr
    | AbstInst.CltUn -> "clt.un" |> pr
    //| AbstInst.Ldftn of MetadataToken
    //| AbstInst.Ldvirtftn of MetadataToken
    | AbstInst.Localloc -> "localloc" |> pr
    | AbstInst.Endfilter -> "endfilter" |> pr
    //| AbstInst.Initobj of MetadataToken
    | AbstInst.Cpblk -> "cpblk" |> pr
    //| AbstInst.Initblk of byte option
    | AbstInst.Rethrow -> "rethrow" |> pr
    //| AbstInst.Sizeof of MetadataToken
    | AbstInst.Refanytype -> "refanytype" |> pr
    | _ ->
        //sprintf "TODO %A" inst |> pr
        "TODO" |> pr

let custModString (cm : CustomModBlob) =
    let reqStr =
        if cm.isRequired then
            "modreq"
        else
            "modopt"
    sprintf "%s (%s)" reqStr cm.theType.FullName

let methSigToString (methSig : MethodDefOrRefSig) =
    "TODO_METH_SIG"

let shapeString (arrShape : ArrayShape) =
    commaSepStrs [|
        for i = 0 to int arrShape.rank - 1 do
            let hasLoBound = i < arrShape.loBounds.Length
            let loBound() = int arrShape.loBounds.[i]
            let hasSize = i < arrShape.sizes.Length
            let size() = int arrShape.sizes.[i]

            if hasLoBound then
                yield string <| loBound()
                yield "..."
                if hasSize then
                    yield string <| loBound() + size() - 1
            elif hasSize then
                yield string <| size()
            else
                yield ""
    |]

let rec typeBlobToStr (ty : TypeBlob) =
    match ty with
    | TypeBlob.Boolean -> "bool"
    | TypeBlob.Char -> "char"
    | TypeBlob.I1 -> "int8"
    | TypeBlob.U1 -> "unsigned int8"
    | TypeBlob.I2 -> "int16"
    | TypeBlob.U2 -> "unsigned int16"
    | TypeBlob.I4 -> "int32"
    | TypeBlob.U4 -> "unsigned int32"
    | TypeBlob.I8 -> "int64"
    | TypeBlob.U8 -> "unsigned int64"
    | TypeBlob.R4 -> "float32"
    | TypeBlob.R8 -> "float64"
    | TypeBlob.I -> "native int"
    | TypeBlob.U -> "native unsigned int"
    | TypeBlob.Class tyDefOrRef -> "class " + tyDefOrRef.FullName
    | TypeBlob.MVar i -> "!!" + string i
    | TypeBlob.Object -> "object"
    | TypeBlob.String -> "string"
    | TypeBlob.ValueType tyDefOrRef -> "valuetype " + tyDefOrRef.FullName
    | TypeBlob.Var i -> "!" + string i

    // the following are also in type spec
    | TypeBlob.Ptr (custMods, tyOpt) -> //of List<CustomModBlob> * Option<TypeBlob>
        spaceSepStrs [|
            match tyOpt with
            | None      -> yield "void*"
            | Some ty   -> yield typeBlobToStr ty + "*"

            yield! List.map custModString custMods
        |]

    | TypeBlob.FnPtr methDefOrRef -> // of MethodDefOrRefSig
        spaceSepStrs [|
            yield "method"

            match methDefOrRef.thisKind with
            | ThisKind.NoThis -> ()
            | ThisKind.ExplicitThis -> yield! [|"instance"; "explicit"|]
            | ThisKind.HasThis -> yield "instance"

            yield "*"
            yield "(TODO_PARAMS_GO_HERE)"
        |]
    | TypeBlob.Array (tyBlob, arrShape) ->
        typeBlobToStr tyBlob + "[" + shapeString arrShape + "]"
    | TypeBlob.SzArray (custMods, tyBlob) -> //of List<CustomModBlob> * TypeBlob
        spaceSepStrs [|
            yield typeBlobToStr tyBlob
            yield! List.map custModString custMods
        |]
    // GenericInst bool isClass with false indicating valuetype
    | TypeBlob.GenericInst (isClass, tyDefOrRef, tyBlobs) -> //of bool * TypeDefOrRef * List<TypeBlob>
        spaceSepStrs [|
            "TODO_GENERIC_INST"
        |]

let genConstrToStr (genConstr : TypeDefOrRef) =
    // Partition II 10.1.7 Generic parameters (GenPars)

    // TODO I know this is wrong
    genConstr.FullName

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

let disMethodDef (tw : TextWriter) (indent : uint32) (md : MethodDef) =
    
    // .method MethodHeader '{' MethodBodyItem* '}'
    // MethAttr* [ CallConv ] Type [marshal '(' [NativeType] ')']
    //           MethodName [ '<' GenPars '>' ] '(' Parameters ')' ImplAttr*
    
    let methodHeader = [|
        yield ".method"

        // method attributes
        if md.IsAbstract then yield "abstract"
        
        yield
            match md.MemberAccess with
            | MemberAccess.Assem -> "assembly"
            | MemberAccess.CompilerControlled -> "compilercontrolled"
            | MemberAccess.FamANDAssem -> "famandassem"
            | MemberAccess.Family -> "family"
            | MemberAccess.FamORAssem -> "famorassem"
            | MemberAccess.Private -> "private"
            | MemberAccess.Public -> "public"

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
        yield
            match methSig.callingConv with
            | MethCallingConv.Default | MethCallingConv.Generic _ ->
                // TODO are we supposed to yield "default" for generic
                "default"
            | MethCallingConv.Vararg ->
                "vararg"
        
        yield! List.map custModString methSig.retType.customMods

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
                    let tyStr = typeBlobToStr specLocalVar.mayByRefType.ty
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
                disInst tw indent blockLabels currAddr inst
                currAddr <- currAddr + instSize

    ifprintfn tw indent "}"

let rec disTypeDef (tw : TextWriter) (indent : uint32) (td : TypeDef) =
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
        | Some ty ->
            yield "extends"

            // TODO need to add something along the lines of "[assembly name]" to this
            yield ty.FullName

        // an optional list of interfaces
        let imps = td.Implements
        if not (Array.isEmpty imps) then
            yield "implements"
            // TODO need to add something along the lines of "[assembly name]" to this
            yield commaSepStrs [|for imp in imps -> imp.FullName|]
    |]

    ifprintfn tw indent "%s" (spaceSepStrs classHeaderStrs)
    ifprintfn tw indent "{"

    Array.iter (disMethodDef tw (indent + 1u)) td.Methods
    Array.iter (disTypeDef tw (indent + 1u)) td.NestedTypes

    ifprintfn tw indent "}"

let disModule (tr : TextWriter) (m : Module) =
    fprintfn tr ".module %s" m.Name
    tr.WriteLine()

    for td in m.TypeDefs do
        disTypeDef tr 1u td

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
    for m in modules do disModule tw m
