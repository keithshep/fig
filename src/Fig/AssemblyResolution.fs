module Fig.AssemblyResolution

open Fig.AssemblyParser
open Fig.IOUtil

open System.IO

type MonoAssemblyResolution(gacPaths : string array) =
    interface IAssemblyResolution with
        member x.ResolveAssembly(assemRef : AssemblyRef) : Assembly =
            let tokStr =
                match assemRef.PublicKeyOrToken with
                | Some tok -> Array.map (sprintf "%02X") tok |> Array.fold (+) ""
                | None -> failwithf "cannot build path for %s" assemRef.Name
            let gacSubFolder = assemRef.Version + "__" + tokStr

            let rec go (i : int) =
                if i < gacPaths.Length then
                    //let currPath = gacPaths.[i]
                    let fullPath =
                        Path.Combine(
                            gacPaths.[i],
                            assemRef.Name,
                            gacSubFolder,
                            assemRef.Name + ".dll")
                    printfn "checking for assembly at: %s" fullPath
                    if File.Exists fullPath then
                        use r = new PosStackBinaryReader(new FileStream(fullPath, FileMode.Open))
                        new Assembly(r, x)
                    else
                        go (i + 1)
                else
                    failwith "Failed to find gac for %s" assemRef.Name
            go 0
