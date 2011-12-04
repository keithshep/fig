open Fig.CecilExt
open Fig.LLVMCodeGen

open Mono.Cecil

open LLVM.Generated.Core
open LLVM.Core
open LLVM.Generated.ExecutionEngine
open LLVM.ExecutionEngine
open LLVM.Generated.Target
open LLVM.Generated.BitWriter

let objRefAsOption = function
    | null -> None
    | x -> Some x

[<EntryPoint>]
let main args =
    match args with
    | [| inAssemFile; outBitcodeFile |] ->
        let assem = AssemblyDefinition.ReadAssembly inAssemFile
        let llvmModuleRef = moduleCreateWithName "module"
        genTypeDefs (objRefAsOption assem.EntryPoint) llvmModuleRef assem.MainModule.Types
        
        // for debug only
        dumpModule llvmModuleRef
        
        writeBitcodeToFile llvmModuleRef outBitcodeFile |> ignore

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

