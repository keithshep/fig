open Fig.AbstractCode
open Fig.AssemblyParser

open System.IO

[<EntryPoint>]
let main args =
    match args with
    | [|inFile|] ->

        use r = new PosStackBinaryReader(new FileStream(inFile, FileMode.Open))
        let pe = readPEHeader r
        let secHdrs = readSectionHeaders r pe
        for hdr in secHdrs do
            printfn "SECTION HEADER:"
            printfn "%A" hdr
        let cliHeader = readCLIHeader r secHdrs pe
        let streamHeaders = readStreamHeaders r secHdrs cliHeader
        let mt = readMetadataTables r secHdrs cliHeader streamHeaders
        for i in 0 .. mt.methodDefs.Length - 1 do
            let md = new MethodDef (r, secHdrs, mt, i)
            printfn ""
            printfn "METHOD BODY"
            match md.MethodBody with
            | None -> printfn "    EMPTY"
            | Some (instBlks, exceptionSecs) ->

                printfn "    ABST INSTRUCTIONS"
                for blkIndex in 0 .. instBlks.Length - 1 do
                    printfn "        BLOCK #%i" blkIndex
                    for inst in instBlks.[blkIndex] do
                        printfn "            %A" inst

                if not (Array.isEmpty exceptionSecs) then
                    printfn "    EXCEPTION SECTION:"
                    for exSec in exceptionSecs do
                        printfn "        %A" exSec

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

