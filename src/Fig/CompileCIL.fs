open System.IO

open Fig.AssemblyParser
open Fig.AssemblyResolution
open Fig.IOUtil
open Fig.LLVMCodeGen

open LLVM.Generated.Core
open LLVM.Core
open LLVM.Generated.ExecutionEngine
open LLVM.ExecutionEngine
open LLVM.Generated.Target
open LLVM.Generated.BitWriter
open LLVM.BitReader

[<EntryPoint>]
let main args =
    match args with
    | [| inAssemFile; outBitcodeFile |] ->
        use r = new PosStackBinaryReader(new FileStream(inAssemFile, FileMode.Open))
        let assem =
            let gacPaths = [|"/Library/Frameworks/Mono.framework/Versions/2.10.5/lib/mono/gac/"|]
            new Assembly(r, new MonoAssemblyResolution(gacPaths))
        //let llvmModuleRef = moduleCreateWithName "module"
        let llvmModuleRef =
            createMemoryBufferWithContentsOfFile "build/fig_runtime.bc"
            |> parseBitcode
        
        genTypeDefs llvmModuleRef assem
        
        // for debug only
        //dumpModule llvmModuleRef
        
        writeBitcodeToFile llvmModuleRef outBitcodeFile |> ignore

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

