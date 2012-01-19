module Fig.IOUtil

open System.IO
open System.Text

let warnf fmt = eprintfn fmt
let failwithf fmt = Printf.ksprintf failwith fmt

// PosStackBinaryReader is a binary reader that allows you to push and pop the
// file position which can be more convenient than explicit seeks
type PosStackBinaryReader(stream : Stream) =
    inherit BinaryReader(stream)

    let mutable posStack = []

    member x.PushPos () = posStack <- stream.Position :: posStack

    member x.PushPos (pos : int64) =
        x.PushPos ()
        stream.Seek (pos, SeekOrigin.Begin) |> ignore

    member x.PopPos () =
        match posStack with
        | headPos :: stackTail ->
            posStack <- stackTail
            stream.Seek (headPos, SeekOrigin.Begin) |> ignore
        | [] ->
            failwith "attempted to pop an empty position stack"

let readBytesEq (r : BinaryReader) (expectBytes : byte array) (name : string) =
    let inBytes = r.ReadBytes expectBytes.Length
    if inBytes <> expectBytes then
        //failwith (sprintf "expected \"%s\" to be %A but read %A" name expectBytes inBytes)
        printfn "expected \"%s\" to be %A but read %A" name expectBytes inBytes

let readByteEq (r : BinaryReader) (expectByte : byte) (name : string) =
    let inByte = r.ReadByte ()
    if inByte <> expectByte then
        //failwith (sprintf "expected \"%s\" to be 0x%X but read 0x%X" name expectByte inByte)
        printfn "expected \"%s\" to be 0x%X but read 0x%X" name expectByte inByte

let readShortEq (r : BinaryReader) (expectShort : uint16) (name : string) =
    let inShort = r.ReadUInt16 ()
    if inShort <> expectShort then
        //failwith (sprintf "expected \"%s\" to be 0x%X but read 0x%X" name expectShort inShort)
        printfn "expected \"%s\" to be 0x%X but read 0x%X" name expectShort inShort

let readIntEq (r : BinaryReader) (expectInt : uint32) (name : string) =
    let inInt = r.ReadUInt32 ()
    if inInt <> expectInt then
        //failwith (sprintf "expected \"%s\" to be 0x%X but read 0x%X" name expectInt inInt)
        printfn "expected \"%s\" to be 0x%X but read 0x%X" name expectInt inInt

let readLongEq (r : BinaryReader) (expectLong : uint64) (name : string) =
    let inLong = r.ReadUInt64 ()
    if inLong <> expectLong then
        printfn "expected \"%s\" to be 0x%X but read 0x%X" name expectLong inLong

let readString (r : BinaryReader) (enc : Encoding) =
    enc.GetString [|
        let currByte = ref (r.ReadByte ())
        while !currByte <> 0uy do
            yield !currByte
            currByte := r.ReadByte ()|]

let readASCII (r : BinaryReader) = readString r Encoding.ASCII

let readUTF8 (r : BinaryReader) = readString r Encoding.UTF8

let readFixedASCII (r : BinaryReader) (fixedLen : int) =
    let sb = new StringBuilder(fixedLen)
    let bytes = r.ReadBytes fixedLen
    let mutable i = 0
    while i < bytes.Length && bytes.[i] <> 0uy do
        sb.Append (char bytes.[i]) |> ignore
        i <- i + 1
    sb.ToString ()

let readAlignedASCII (r : BinaryReader) (align : int) =
    let sb = new StringBuilder()
    let mutable currByte = r.ReadByte ()
    let mutable bytesRead = 1
    while currByte <> 0uy do
        sb.Append (char currByte) |> ignore
        currByte <- r.ReadByte ()
        bytesRead <- bytesRead + 1
    let overhang = bytesRead % align
    if overhang <> 0 then
        let padding = align - overhang
        r.BaseStream.Seek (int64 padding, SeekOrigin.Current) |> ignore
    sb.ToString ()
