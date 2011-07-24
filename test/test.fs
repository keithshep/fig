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
        let metadataTables = readMetadataTables br secHdrs cliHeader streamHeaders
        ()
        
    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

