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
    "TODO"

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
            yield "(" + (commaSepStrs <| Array.map genConstrToStr genConstrs) + ")"

        yield genPar.Name
    |]

    spaceSepStrs genParStrs

let disTypeDef (tr : TextWriter) (indent : uint32) (td : TypeDef) =
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

        // an optional list of interfaces
    |]

    ifprintfn tr indent "%s" (spaceSepStrs classHeaderStrs)
    ifprintfn tr indent "{"
    ifprintfn tr indent "}"

let disassemble (tr : TextWriter) (assem : Assembly) =
    for ar in assem.AssemblyRefs do
        fprintfn tr ".assembly extern %s" ar.Name
        fprintfn tr "{"
        ifprintfn tr 1u ".ver %s" (versionString ar)
        match ar.PublicKeyOrToken with
        | None -> ()
        | Some pubKeyOrTok ->
            if not ar.IsPublicKeySet then
                ifprintfn tr 1u ".publickeytoken = (%s)" (bytesToString pubKeyOrTok)
            else
                failwith "implement me dude"

        fprintfn tr "}"

    fprintfn tr ".assembly %s" assem.Name
    fprintfn tr "{"

    for td in assem.TypeDefs do
        disTypeDef tr 1u td

    fprintfn tr "}"

    //for assem in assem.MetadataTables.assemblies do
    //    fprint