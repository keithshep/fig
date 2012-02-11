module Fig.Disassemble

open Fig.AssemblyParser
open Fig.IOUtil

open System.IO
open System.Text

let sepStrsWith (sep : string) (strings : string array) =
    if Array.isEmpty strings then
        ""
    else
        let sb = new StringBuilder()
        sb.Append strings.[0] |> ignore
        for i in 1 .. strings.Length - 1 do
            sb.Append sep |> ignore
            sb.Append strings.[i] |> ignore
        sb.ToString()
let spaceSepStrs = sepStrsWith " "
let commaSepStrs = sepStrsWith ", "

let bytesToString (bytes : byte array) =
    spaceSepStrs <| Array.map (sprintf "%02X") bytes

let versionString (assemRef : AssemblyRef) =
    string assemRef.MajorVersion + ":" +
    string assemRef.MinorVersion + ":" +
    string assemRef.RevisionNumber + ":" +
    string assemRef.BuildNumber

let genConstrToStr (genConstr : TypeDefOrRef) =
    // Partition II 10.1.7 Generic parameters (GenPars)

    // TODO I know this is wrong
    genConstr.FullName

let genParToStr (genPar : GenericParam) =
    // Partition II 10.1.7 Generic parameters (GenPars)
    let genParStrs = [|
        match genPar.Variance with
        | GenericParamVariance.Covariant -> yield "+"
        | GenericParamVariance.Contravariant -> yield "-"
        | GenericParamVariance.None -> () // no-op
        
        match genPar.SpecialConstraint with
        | SpecialConstraint.None -> () // no-op
        | SpecialConstraint.ReferenceType -> yield "class"
        | SpecialConstraint.NotNullableValueType -> yield "valuetype"
        | SpecialConstraint.DefaultConstructor -> yield ".ctor"

        let genConstrs = Array.ofSeq genPar.Constraints
        if not <| Array.isEmpty genConstrs then
            yield "(" + commaSepStrs (Array.map genConstrToStr genConstrs) + ")"

        yield genPar.Name
    |]

    spaceSepStrs genParStrs

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

        yield md.Name
    |]

    ifprintfn tw indent "%s ()" (spaceSepStrs methodHeader)
    ifprintfn tw indent "{"
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
