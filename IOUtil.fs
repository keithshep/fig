module Fig.IOUtil

open System.IO
open System.Text

let private indentStr = "  "

// an indented version of the fprintfn function
let ifprintf (tr : TextWriter) (depth : uint32) fmt =
    let printIndented (s : string) =
        for _ in 1u .. depth do
            tr.Write indentStr
        tr.Write s
    Printf.ksprintf printIndented fmt

let ifprintfn (tr : TextWriter) (depth : uint32) fmt =
    let printIndented (s : string) =
        for _ in 1u .. depth do
            tr.Write indentStr
        tr.WriteLine s
    Printf.ksprintf printIndented fmt

//let debugfn fmt = printfn fmt
//let debugfn fmt = Printf.ksprintf System.Diagnostics.Debug.WriteLine fmt
let debugfn fmt = Printf.ksprintf (fun _ -> ()) fmt

let sepStrsWith (sep : string) (strings : string array) =
    if Array.isEmpty strings then
        ""
    else
        let sb = new StringBuilder()
        sb.Append strings.[0] |> ignore
        for i in 1 .. strings.Length - 1 do
            sb.Append sep |> ignore
            sb.Append strings.[i] |> ignore
        sb.ToString()
let spaceSepStrs = sepStrsWith " "
let commaSepStrs = sepStrsWith ", "

// TODO make sure all of these list functions are actually used in the final versions
let listRead (xs : 'a list ref) : 'a option =
    match !xs with
    | [] -> None
    | x :: xt ->
        xs := xt
        Some x
let listSkip (xs : 'a list ref) : unit =
    match !xs with
    | [] -> failwith "cannot skip an empty list"
    | _ :: xt -> xs := xt

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
        debugfn "expected \"%s\" to be %A but read %A" name expectBytes inBytes

let readByteEq (r : BinaryReader) (expectByte : byte) (name : string) =
    let inByte = r.ReadByte ()
    if inByte <> expectByte then
        debugfn "expected \"%s\" to be 0x%X but read 0x%X" name expectByte inByte

let readShortEq (r : BinaryReader) (expectShort : uint16) (name : string) =
    let inShort = r.ReadUInt16 ()
    if inShort <> expectShort then
        debugfn "expected \"%s\" to be 0x%X but read 0x%X" name expectShort inShort

let readIntEq (r : BinaryReader) (expectInt : uint32) (name : string) =
    let inInt = r.ReadUInt32 ()
    if inInt <> expectInt then
        debugfn "expected \"%s\" to be 0x%X but read 0x%X" name expectInt inInt

let readLongEq (r : BinaryReader) (expectLong : uint64) (name : string) =
    let inLong = r.ReadUInt64 ()
    if inLong <> expectLong then
        debugfn "expected \"%s\" to be 0x%X but read 0x%X" name expectLong inLong

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

type ElementType =
    | End           = 0x00
    | Void          = 0x01
    | Boolean       = 0x02
    | Char          = 0x03
    | I1            = 0x04
    | U1            = 0x05
    | I2            = 0x06
    | U2            = 0x07
    | I4            = 0x08
    | U4            = 0x09
    | I8            = 0x0A
    | U8            = 0x0B
    | R4            = 0x0C
    | R8            = 0x0D
    | String        = 0x0E
    | Ptr           = 0x0F
    | ByRef         = 0x10
    | ValueType     = 0x11
    | Class         = 0x12
    | Var           = 0x13
    | Array         = 0x14
    | GenericInst   = 0x15
    | TypedByRef    = 0x16
    | I             = 0x18
    | U             = 0x19
    | FnPtr         = 0x1B
    | Object        = 0x1C
    | SzArray       = 0x1D
    | MVar          = 0x1E
    | CmodReqd      = 0x1F
    | CmodOpt       = 0x20
    | Internal      = 0x21
    | Modifier      = 0x40
    | Sentinel      = 0x41
    | Pinned        = 0x45
    | SysType       = 0x50
    | Boxed         = 0x51
    | Reserved      = 0x52
    | Field         = 0x53
    | Property      = 0x54
    | Enum          = 0x55

let rec readBlobWhile (test : byte -> bool) (f : byte list ref -> 'a) (bytes : byte list ref) : 'a list =
    match !bytes with
    | fstByte :: _ when test fstByte ->
        f bytes :: readBlobWhile test f bytes
    | _ -> []

let (|ElTy|) (b : byte) = enum<ElementType> (int b)

// defined in section 23.2: compressed integers are stored big-endian
let makeReadByteFun (xs : byte list ref) : unit -> byte =
    fun () ->
        match listRead xs with
        | None -> failwith "unexpected end of byte list"
        | Some b -> b
let readCompressedUnsignedInt (readByte : unit -> byte) : uint32 =
    let b1 = readByte() |> uint32
    // If the value lies between 0 (0x00) and 127 (0x7F), inclusive, encode
    // as a one-byte integer (bit 7 is clear, value held in bits 6 through 0)
    if b1 &&& 0b10000000u = 0u then
        // it's a 1 byte integer
        b1
    else
        // If the value lies between 28 (0x80) and 214 – 1 (0x3FFF), inclusive,
        // encode as a 2-byte integer with bit 15 set, bit 14 clear (value held
        // in bits 13 through 0). Otherwise, encode as a 4-byte integer, with
        // bit 31 set, bit 30 set, bit 29 clear (value held in bits 28 through 0)
        let maskedB1 = b1 &&& 0b00111111u
        let b2 = readByte() |> uint32
        if b1 &&& 0b01000000u = 0u then
            // it's a 2 byte integer
            (maskedB1 <<< 8) ||| b2
        else
            // it's a 4 byte integer
            if b1 &&& 0b00100000u <> 0u then
                failwith "expected bit 29 to be clear for an compressed unisigned int"
            let b3 = readByte() |> uint32
            let b4 = readByte() |> uint32
            (maskedB1 <<< 24) ||| (b2 <<< 16) ||| (b3 <<< 8) ||| b4
let readCompressedInt (readByte : unit -> byte) : int =
    let x = int (readCompressedUnsignedInt readByte >>> 1)
    if   x &&& 1 = 0    then x
    elif x < 0x40       then x - 0x40
    elif x < 0x2000     then x - 0x2000
    elif x < 0x10000000 then x - 0x10000000
    else                     x - 0x20000000
