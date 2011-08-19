open Fig.LLVMCodeGen

open Microsoft.FSharp.Compiler.AbstractIL.IL
open Microsoft.FSharp.Compiler.AbstractIL.ILBinaryReader

open LLVM.Generated.Core
open LLVM.Core
open LLVM.Generated.ExecutionEngine
open LLVM.ExecutionEngine
open LLVM.Generated.Target
open LLVM.Generated.BitWriter

[<EntryPoint>]
let main args =
    match args with
    | [| inFile; outFile |] ->
        let il = OpenILModuleReader inFile defaults
        let moduleRef = moduleCreateWithName "module"
        genTypeDefs moduleRef il.ILModuleDef.TypeDefs
        dumpModule moduleRef
        writeBitcodeToFile moduleRef outFile |> ignore

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

