open Fig.AssemblyParser
open Fig.AssemblyResolution
open Fig.Disassemble
open Fig.IOUtil

open System.IO

[<EntryPoint>]
let main args =
    match args with
    | [|inFile|] ->

        use r = new PosStackBinaryReader(new FileStream(inFile, FileMode.Open))
        let assem =
            let gacPaths = [|"/Library/Frameworks/Mono.framework/Versions/2.10.5/lib/mono/gac/"|]
            new Assembly(r, new MonoAssemblyResolution(gacPaths))
        disassemble System.Console.Out assem

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

