module Fig.AssemblyResolution

open Fig.AssemblyParser
open Fig.IOUtil

open System.Collections.Generic
open System.IO

type MonoAssemblyResolution(gacPaths:string array,
                            mscorMajor:uint16,
                            mscorMinor:uint16,
                            mscorRevision:uint16,
                            mscorBuild:uint16) as x =
    let assemKey (assemBase : AssemblyBase) = assemBase.Name, assemBase.Version
    let assemCache = new Dictionary<string * string, Assembly>()
    let newPSBReader (path : string) =
        new PosStackBinaryReader(new FileStream(path, FileMode.Open))
    let mscorlib = lazy (
        let rec go (i : int) : MscorlibAssembly =
            let monoVersionDir =
                match mscorMajor, mscorRevision with
                | 1us, _ -> "1.0"
                | 2us, 5us -> "2.1"
                | 2us, _ -> "2.0"
                | 4us, _ -> "4.0"
                | maj, rev -> failwithf "unsupported mscorlib major-version=%i, revision-number=%i" maj rev
            let fullPath = Path.Combine(gacPaths.[i], "..", monoVersionDir, "mscorlib.dll")
            //debugfn "checking for mscorlib at: %s" fullPath
            if File.Exists fullPath then
                new MscorlibAssembly(newPSBReader fullPath, x)
            else
                go (i + 1)
        go 0
    )

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

                match assemRef.Name with
                | "mscorlib" ->
                    let mscorl = mscorlib.Value
                    let badVersion() =
                        mscorl.MajorVersion <> mscorMajor || mscorl.MinorVersion <> mscorMinor
                        || mscorl.RevisionNumber <> mscorRevision || mscorl.BuildNumber <> mscorBuild
                    if badVersion() then
                        failwith "unexpected mscorlib version: %s" mscorl.Version
                    upcast mscorl
                | assemName ->
                    let rec go (i : int) =
                        let notFound() = failwithf "Failed to find gac for %s" assemName
                        if i < gacPaths.Length then
                            let fullPath =
                                Path.Combine(
                                    gacPaths.[i],
                                    assemName,
                                    gacSubFolder,
                                    assemName + ".dll")
                            //debugfn "checking for assembly %s at: %s" assemName fullPath
                            if File.Exists fullPath then
                                new Assembly(newPSBReader fullPath, x)
                            else
                                go (i + 1)
                        else
                            notFound()

                    go 0

        member x.RegisterAssembly (assem : Assembly) =
            assemCache.[assemKey assem] <- assem

        member x.Mscorlib : MscorlibAssembly = mscorlib.Value
