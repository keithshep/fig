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
            let gacPaths = [|"/Library/Frameworks/Mono.framework/Versions/2.10.9/lib/mono/gac/"|]
            new Assembly(r, new MonoAssemblyResolution(gacPaths, 4us, 0us, 0us, 0us))
        let llvmModuleRef = moduleCreateWithName "module"
        
        try
            genTypeDefs llvmModuleRef assem
        
            // for debug only
            //dumpModule llvmModuleRef
            
            writeBitcodeToFile llvmModuleRef outBitcodeFile |> ignore

            // exit success
            0
        with ex ->
            // try to dump as much info as possible before quitting
            printfn "%A" ex
            writeBitcodeToFile llvmModuleRef outBitcodeFile |> ignore

            // exit failure
            1

    | _ -> failwith (sprintf "bad options %A" args)

