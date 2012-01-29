module Fig.IOUtil

open System.IO
open System.Text

// an indented version of the fprintfn function
let ifprintf (tr : TextWriter) (depth : uint32) fmt =
    let printIndented (s : string) =
        for _ in 1u .. depth do
            tr.Write "    "
        tr.Write s
    Printf.ksprintf printIndented fmt

let ifprintfn (tr : TextWriter) (depth : uint32) fmt =
    let printIndented (s : string) =
        for _ in 1u .. depth do
            tr.Write "    "
        tr.WriteLine s
    Printf.ksprintf printIndented fmt

// TODO make sure all of these list functions are actually used in the final versions
let listRead (xs : 'a list ref) : 'a option =
    match !xs with
    | [] -> None
    | x :: xt ->
        xs := xt
        Some x
let listPeek (xs : 'a list ref) : 'a option =
    match !xs with
    | [] -> None
    | x :: _ -> Some x
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

type [<RequireQualifiedAccess>] ElementType =
    | End // 0x00 Marks end of a list
    | Void // 0x01
    | Boolean // 0x02
    | Char // 0x03
    | I1 // 0x04
    | U1 // 0x05
    | I2 // 0x06
    | U2 // 0x07
    | I4 // 0x08
    | U4 // 0x09
    | I8 // 0x0a
    | U8 // 0x0b
    | R4 // 0x0c
    | R8 // 0x0d
    | String // 0x0e
    | Ptr // 0x0f  Followed by type
    | ByRef // 0x10  Followed by type
    | ValueType // 0x11  Followed by TypeDef or TypeRef token
    | Class // 0x12  Followed by TypeDef or TypeRef token
    | Var // 0x13  Generic parameter in a generic type definition, represented as number (compressed unsigned integer)
    | Array // 0x14  type rank boundsCount bound1 … loCount lo1 …
    | GenericInst // 0x15  Generic type instantiation.  Followed by type type-arg-count  type-1 ... type-n
    | TypedByRef // 0x16
    | I // 0x18  System.IntPtr
    | U // 0x19  System.UIntPtr
    | FnPtr // 0x1b  Followed by full method signature
    | Object // 0x1c  System.Object
    | SzArray // 0x1d  Single-dim array with 0 lower bound
    | MVar // 0x1e  Generic parameter in a generic method definition, represented as number (compressed unsigned integer)
    | CmodReqd // 0x1f  Required modifier : followed by a TypeDef or TypeRef token
    | CmodOpt // 0x20  Optional modifier : followed by a TypeDef or TypeRef token
    | Internal // 0x21  Implemented within the CLI
    | Modifier // 0x40  Or’d with following element types
    | Sentinel // 0x41  Sentinel for vararg method signature
    | Pinned // 0x45  Denotes a local variable that points at a pinned object
    | SysType // 0x50  Indicates an argument of type System.Type.
    | Boxed // 0x51  Used in custom attributes to specify a boxed object (§23.3).
    | Reserved // 0x52  Reserved
    | Field // 0x53  Used in custom attributes to indicate a FIELD (§22.10, 23.3).
    | Property // 0x54  Used in custom attributes to indicate a PROPERTY (§22.10, 23.3).
    | Enum // 0x55  Used in custom attributes to specify an enum (§23.3).
    with
        static member FromByte = function
            | 0x00uy -> ElementType.End
            | 0x01uy -> ElementType.Void
            | 0x02uy -> ElementType.Boolean
            | 0x03uy -> ElementType.Char
            | 0x04uy -> ElementType.I1
            | 0x05uy -> ElementType.U1
            | 0x06uy -> ElementType.I2
            | 0x07uy -> ElementType.U2
            | 0x08uy -> ElementType.I4
            | 0x09uy -> ElementType.U4
            | 0x0auy -> ElementType.I8
            | 0x0buy -> ElementType.U8
            | 0x0cuy -> ElementType.R4
            | 0x0duy -> ElementType.R8
            | 0x0euy -> ElementType.String
            | 0x0fuy -> ElementType.Ptr
            | 0x10uy -> ElementType.ByRef
            | 0x11uy -> ElementType.ValueType
            | 0x12uy -> ElementType.Class
            | 0x13uy -> ElementType.Var
            | 0x14uy -> ElementType.Array
            | 0x15uy -> ElementType.GenericInst
            | 0x16uy -> ElementType.TypedByRef
            | 0x18uy -> ElementType.I
            | 0x19uy -> ElementType.U
            | 0x1buy -> ElementType.FnPtr
            | 0x1cuy -> ElementType.Object
            | 0x1duy -> ElementType.SzArray
            | 0x1euy -> ElementType.MVar
            | 0x1fuy -> ElementType.CmodReqd
            | 0x20uy -> ElementType.CmodOpt
            | 0x21uy -> ElementType.Internal
            | 0x40uy -> ElementType.Modifier
            | 0x41uy -> ElementType.Sentinel
            | 0x45uy -> ElementType.Pinned
            | 0x50uy -> ElementType.SysType
            | 0x51uy -> ElementType.Boxed
            | 0x52uy -> ElementType.Reserved
            | 0x53uy -> ElementType.Field
            | 0x54uy -> ElementType.Property
            | 0x55uy -> ElementType.Enum
            | tyCode -> failwithf "0x%X is not a valid type code" tyCode

        static member UntilEnd (f : byte list ref -> 'a) (bytes : byte list ref) : 'a list =
            // TODO pretty inefficient
            match !bytes with
            | [] -> failwith "unexpected end of blob in UntilEnd"
            | fstByte :: _ ->
                match ElementType.FromByte fstByte with
                | ElementType.End -> []
                | _ ->
                    let currVal = f bytes
                    currVal :: ElementType.UntilEnd f bytes

let (|ElTy|) (b : byte) = ElementType.FromByte b

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
