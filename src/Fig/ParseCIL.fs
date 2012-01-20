open Fig.AbstractCode
open Fig.AssemblyParser
open Fig.IOUtil

open System.IO

[<EntryPoint>]
let main args =
    match args with
    | [|inFile|] ->

        use r = new PosStackBinaryReader(new FileStream(inFile, FileMode.Open))
        let assem = new Assembly(r)
        let mt = assem.MetadataTables
        for i in 0 .. mt.methodDefs.Length - 1 do
            let md = new MethodDef(r, assem, i)
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

