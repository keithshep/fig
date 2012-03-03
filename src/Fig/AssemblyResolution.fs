module Fig.AssemblyResolution

open Fig.AssemblyParser
open Fig.IOUtil

open System.Collections.Generic
open System.IO

type MonoAssemblyResolution(gacPaths : string array) =
    let assemKey (ar : AssemblyBase) = ar.Name, ar.Version
    let assemCache = new Dictionary<string * string, Assembly>()

    interface IAssemblyResolution with
        member x.ResolveAssembly(assemRef : AssemblyRef) : Assembly =
            let key = assemKey assemRef
            if assemCache.ContainsKey key then
                assemCache.[key]
            else
                let tokStr =
                    match assemRef.PublicKeyOrToken with
                    | Some tok -> Array.map (sprintf "%02X") tok |> Array.fold (+) ""
                    | None -> failwithf "cannot build path for %s" assemRef.Name
                let gacSubFolder = assemRef.Version + "__" + tokStr

                let rec go (i : int) =
                    if i < gacPaths.Length then
                        let fullPath =
                            Path.Combine(
                                gacPaths.[i],
                                assemRef.Name,
                                gacSubFolder,
                                assemRef.Name + ".dll")
                        printfn "checking for assembly at: %s" fullPath
                        if File.Exists fullPath then
                            use r = new PosStackBinaryReader(new FileStream(fullPath, FileMode.Open))
                            let assem = new Assembly(r, x)
                            assemCache.[key] <- assem
                            assem
                        else
                            go (i + 1)
                    else
                        failwith "Failed to find gac for %s" assemRef.Name
                go 0

        member x.RegisterAssembly (assem : Assembly) =
            assemCache.[assemKey assem] <- assem
