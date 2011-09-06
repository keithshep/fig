open Fig.CecilExt
open Mono.Cecil

// an indented version of the printf function
let iprintfn depth fmt =
    let printIndented s =
        for i = 0 to depth - 1 do
            printf "    "
        printfn "%s" s
    Printf.ksprintf printIndented fmt

// test driver code
[<EntryPoint>]
let main args =
    match args with
    | [|assemFile|] ->
        let assem = AssemblyDefinition.ReadAssembly assemFile
        let mainModule = assem.MainModule
        for ty in assem.MainModule.Types do
            printfn "Type: %s" ty.FullName
            for meth in ty.Methods do
                iprintfn 1 "Method: %s" meth.FullName
                let paramToStr (p : ParameterDefinition) =
                    sprintf "param=%A, type=%A"
                        p
                        (toSaferType p.ParameterType)
                let printParams () =
                    for param in meth.Parameters do
                        iprintfn 2 "Parameter: %s" (paramToStr param)
                
                let body = meth.Body
                match body with
                | null ->
                    printParams()
                    iprintfn 2 "Empty Method"
                | _ ->
                    if meth.HasThis then
                        iprintfn 2 "ThisParameter: %s" (paramToStr body.ThisParameter)
                    printParams()
                    iprintfn 2 "Non-empty Method"
//                    for block in body.CodeBlocks do
//                        iprintfn 2 "Block: %i" block.OffsetBytes
//                        for inst in block.Instructions do
//                            iprintfn 3 "%A" inst

        // exit success
        0
    | _ ->
        failwith "bad command line args"

