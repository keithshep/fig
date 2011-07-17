open Fig.LLVMCodeGen
open Fig.CIL

open Microsoft.FSharp.Compiler.AbstractIL.IL
open Microsoft.FSharp.Compiler.AbstractIL.ILBinaryReader

open LLVM.Generated.Core
open LLVM.Core
open LLVM.Generated.ExecutionEngine
open LLVM.ExecutionEngine
open LLVM.Generated.Target
open LLVM.Generated.BitWriter

open System.IO

[<EntryPoint>]
let main args =
    match args with
    | [| inFile; outFile |] ->

        use br = new DLLReader(new FileStream(inFile, FileMode.Open))
        let pe = readPEHeader br
        let secHdrs = readSectionHeaders br pe
        for hdr in secHdrs do
            printfn "SECTION HEADER:"
            printfn "%A" hdr
        let cliHeader = readCLIHeader br secHdrs pe
        let streamHeaders = readStreamHeaders br secHdrs cliHeader
        readMetadataTables br secHdrs cliHeader streamHeaders
        
//        let il = OpenILModuleReader inFile defaults
//        let moduleRef = moduleCreateWithName "module"
//        genTypeDefs moduleRef il.ILModuleDef.TypeDefs
//        dumpModule moduleRef
//        writeBitcodeToFile moduleRef outFile |> ignore

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

