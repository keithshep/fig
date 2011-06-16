open Fig.LLVMCodeGen

open Microsoft.FSharp.Compiler.AbstractIL.IL
open Microsoft.FSharp.Compiler.AbstractIL.ILBinaryReader

open LLVM.Generated.Core
open LLVM.Core
open LLVM.Generated.ExecutionEngine
open LLVM.ExecutionEngine
open LLVM.Generated.Target

open System.Runtime.InteropServices
[<DllImport("LLVM-2.9.dll", EntryPoint="LLVMInitializeX86Target")>]
extern void initializeX86Target()

[<EntryPoint>]
let main args =
    match args with
    | [| inFile; outFile |] ->
        initializeX86Target ()
        let il = OpenILModuleReader inFile defaults
        let moduleRef = moduleCreateWithName "module"
        genTypeDefs moduleRef il.ILModuleDef.TypeDefs
        LLVM.Generated.BitWriter.writeBitcodeToFile moduleRef outFile |> ignore

//        dumpModule moduleRef
//        let gcd = getNamedFunction moduleRef "gcd"
//        let add = getNamedFunction moduleRef "add"//        let myEng = createExecutionEngineForModule moduleRef
//        
//        let _36 = createGenericValueOfInt (int32Type ()) 36UL false
//        let _81 = createGenericValueOfInt (int32Type ()) 81UL false
//        let result = runFunction myEng add [|_36; _81|]
//        printfn "add(36, 81) -> %i" (genericValueToInt result false)
//        
//        let _36 = createGenericValueOfInt (int32Type ()) 36UL false
//        let _81 = createGenericValueOfInt (int32Type ()) 81UL false
//        let result = runFunction myEng gcd [|_36; _81|]
//        printfn "gcd(36, 81) -> %i" (genericValueToInt result false)
//
//        let run23 = getNamedFunction moduleRef "add23"
//        let result2 = runFunction myEng run23 [||]
//        printfn "add23() -> %i" (genericValueToInt result2 false)
//        printfn "_36 %i" (genericValueToInt _36 false)

    | _ -> failwith (sprintf "bad options %A" args)

    // exit success
    0

