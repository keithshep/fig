open Fig.CIL

open System.IO

[<EntryPoint>]
let main args =
    match args with
    | [|inFile|] ->

        use br = new DLLReader(new FileStream(inFile, FileMode.Open))
        let pe = readPEHeader br
        let secHdrs = readSectionHeaders br pe
        for hdr in secHdrs do
            printfn "SECTION HEADER:"
            printfn "%A" hdr
        let cliHeader = readCLIHeader br secHdrs pe
        let streamHeaders = readStreamHeaders br secHdrs cliHeader
        let mt = readMetadataTables br secHdrs cliHeader streamHeaders
        for i in 0 .. mt.methodDefs.Length - 1 do
            let md = new MethodDef (br, secHdrs, mt, i)
            md.MethodBody

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

