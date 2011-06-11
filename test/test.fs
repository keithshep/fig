open Fig.LLVMCodeGen

open Microsoft.FSharp.Compiler.AbstractIL.IL
open Microsoft.FSharp.Compiler.AbstractIL.ILBinaryReader

open LLVM.Generated.Core
open LLVM.Core

[<EntryPoint>]
let main args =
    match args with
    | [| inFile |] ->
        let il = OpenILModuleReader inFile defaults
        let moduleRef = moduleCreateWithName "myModule"
        
        genTypeDefs moduleRef il.ILModuleDef.TypeDefs
        LLVM.Generated.BitWriter.writeBitcodeToFile moduleRef (inFile + ".bc") |> ignore

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

