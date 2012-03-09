module Fig.AssemblyResolution

open Fig.AssemblyParser
open Fig.IOUtil

open System.Collections.Generic
open System.IO

type MonoAssemblyResolution(gacPaths : string array) =
    let assemKey (assemBase : AssemblyBase) = assemBase.Name, assemBase.Version
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
                    let notFound() = failwithf "Failed to find gac for %s" assemRef.Name
                    let assemFromPath (path : string) =
                        let r = new PosStackBinaryReader(new FileStream(path, FileMode.Open))
                        new Assembly(r, x)
                    if i < gacPaths.Length then
                        let fullPath =
                            Path.Combine(
                                gacPaths.[i],
                                assemRef.Name,
                                gacSubFolder,
                                assemRef.Name + ".dll")
                        debugfn "checking for assembly %s at: %s" assemRef.Name fullPath
                        if File.Exists fullPath then
                            assemFromPath fullPath
                        elif assemRef.Name = "mscorlib" then
                            // TODO this is different on windows
                            let monoVersionDir =
                                match assemRef.MajorVersion, assemRef.RevisionNumber with
                                | 1us, _ -> "1.0"
                                | 2us, 5us -> "2.1"
                                | 2us, _ -> "2.0"
                                | 4us, _ -> "4.0"
                                | maj, rev -> failwithf "unsupported mscorlib major-version=%i, revision-number=%i" maj rev
                            let fullPath = Path.Combine(gacPaths.[i], "..", monoVersionDir, assemRef.Name + ".dll")
                            debugfn "checking for assembly %s at: %s" assemRef.Name fullPath
                            if File.Exists fullPath then
                                assemFromPath fullPath
                            else
                                go (i + 1)
                        else
                            go (i + 1)
                    else
                        notFound()

                go 0

        member x.RegisterAssembly (assem : Assembly) =
            assemCache.[assemKey assem] <- assem
