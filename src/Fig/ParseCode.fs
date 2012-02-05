module Fig.ParseCode

open Fig.IOUtil

open System.IO

type MetadataTableKind =
    | AssemblyKind = 0x20
    | AssemblyOSKind = 0x22
    | AssemblyProcessorKind = 0x21
    | AssemblyRefKind = 0x23
    | AssemblyRefOSKind = 0x25
    | AssemblyRefProcessorKind = 0x24
    | ClassLayoutKind = 0x0F
    | ConstantKind = 0x0B
    | CustomAttributeKind = 0x0C
    | DeclSecurityKind = 0x0E
    | EventMapKind = 0x12
    | EventKind = 0x14
    | ExportedTypeKind = 0x27
    | FieldKind = 0x04
    | FieldLayoutKind = 0x10
    | FieldMarshalKind = 0x0D
    | FieldRVAKind = 0x1D
    | FileKind = 0x26
    | GenericParamKind = 0x2A
    | GenericParamConstraintKind = 0x2C
    | ImplMapKind = 0x1C
    | InterfaceImplKind = 0x09
    | ManifestResourceKind = 0x28
    | MemberRefKind = 0x0A
    | MethodDefKind = 0x06
    | MethodImplKind = 0x19
    | MethodSemanticsKind = 0x18
    | MethodSpecKind = 0x2B
    | ModuleKind = 0x00
    | ModuleRefKind = 0x1A
    | NestedClassKind = 0x29
    | ParamKind = 0x08
    | PropertyKind = 0x17
    | PropertyMapKind = 0x15
    | StandAloneSigKind = 0x11
    | TypeDefKind = 0x02
    | TypeRefKind = 0x01
    | TypeSpecKind = 0x1B

// Partition III Section 1.9 defines metadata tokens
type MetadataToken = MetadataTableKind option * int

let toMetadataToken (mtBytes : uint32) =
    let mutable rowOrIndex =
        // The rows within metadata tables are numbered one upwards,
        // whilst offsets in the heap are numbered zero upwards.
        int (mtBytes &&& 0x00FFFFFFu)
    let optTblKind =
        match mtBytes >>> 24 with
        | 0x70u ->
            // 0x70 indicates this is an index into the string heap
            None
        | n ->
            // adjust the row so that it's zero based
            rowOrIndex <- rowOrIndex - 1
            Some (enum<MetadataTableKind> (int n))

    (optTblKind, rowOrIndex)

let readMetadataToken (r : BinaryReader) = toMetadataToken (r.ReadUInt32 ())

type [<RequireQualifiedAccess>] RawInst =
    | Add
    | And
    | Beq of int
    | Bge of int
    | Bgt of int
    | Ble of int
    | Blt of int
    | BneUn of int
    | BgeUn of int
    | BgtUn of int
    | BleUn of int
    | BltUn of int
    | Br of int
    | Break
    | Brfalse of int
    | Brtrue of int
    | Call of bool * MetadataToken
    | Calli of bool * MetadataToken
    | Callvirt of MetadataToken option * bool * MetadataToken
    | ConvI1
    | ConvI2
    | ConvI4
    | ConvI8
    | ConvR4
    | ConvR8
    | ConvU4
    | ConvU8
    | Cpobj of MetadataToken
    | Div
    | DivUn
    | Dup
    | Jmp of MetadataToken
    | Ldarg of uint16
    | Ldarga of uint16
    | LdcI4 of int
    | LdcI8 of int64
    | LdcR4 of single
    | LdcR8 of double
    | LdindU1 of byte option
    | LdindI2 of byte option
    | LdindU2 of byte option
    | LdindI4 of byte option
    | LdindU4 of byte option
    | LdindI8 of byte option
    | LdindI of byte option
    | LdindR4 of byte option
    | LdindR8 of byte option
    | LdindRef of byte option
    | Ldloc of uint16
    | Ldloca of uint16
    | Ldnull
    | Ldobj of byte option * MetadataToken
    | Ldstr of MetadataToken
    | Mul
    | Neg
    | Nop
    | Not
    | Newobj of MetadataToken
    | Or
    | Pop
    | Rem
    | RemUn
    | Ret
    | Shl
    | Shr
    | ShrUn
    | Starg of uint16
    | StindRef of byte option
    | StindI1 of byte option
    | StindI2 of byte option
    | StindI4 of byte option
    | StindI8 of byte option
    | StindR4 of byte option
    | StindR8 of byte option
    | Stloc of uint16
    | Sub
    | Switch of int array
    | Xor
    | Castclass of MetadataToken
    | Isinst of MetadataToken
    | ConvRUn
    | Unbox of MetadataToken
    | Throw
    | Ldfld of byte option * MetadataToken
    | Ldflda of byte option * MetadataToken
    | Stfld of byte option * MetadataToken
    | Ldsfld of MetadataToken
    | Ldsflda of MetadataToken
    | Stsfld of MetadataToken
    | Stobj of byte option * MetadataToken
    | ConvOvfI1Un
    | ConvOvfI2Un
    | ConvOvfI4Un
    | ConvOvfI8Un
    | ConvOvfU1Un
    | ConvOvfU2Un
    | ConvOvfU4Un
    | ConvOvfU8Un
    | ConvOvfIUn
    | ConvOvfUUn
    | Box of MetadataToken
    | Newarr of MetadataToken
    | Ldlen
    | Ldelema of MetadataToken
    | LdelemI1
    | LdelemU1
    | LdelemI2
    | LdelemU2
    | LdelemI4
    | LdelemU4
    | LdelemI8
    | LdelemI
    | LdelemR4
    | LdelemR8
    | LdelemRef
    | StelemI
    | StelemI1
    | StelemI2
    | StelemI4
    | StelemI8
    | StelemR4
    | StelemR8
    | StelemRef
    | Ldelem of MetadataToken
    | Stelem of MetadataToken
    | UnboxAny of MetadataToken
    | ConvOvfI1
    | ConvOvfU1
    | ConvOvfI2
    | ConvOvfU2
    | ConvOvfI4
    | ConvOvfU4
    | ConvOvfI8
    | ConvOvfU8
    | Refanyval of MetadataToken
    | Ckfinite
    | Mkrefany of MetadataToken
    | Ldtoken of MetadataToken
    | ConvU2
    | ConvU1
    | ConvI
    | ConvOvfI
    | ConvOvfU
    | AddOvf
    | AddOvfUn
    | MulOvf
    | MulOvfUn
    | SubOvf
    | SubOvfUn
    | Endfinally
    | Leave of int
    | StindI of byte option
    | ConvU
    | Arglist
    | Ceq
    | Cgt
    | CgtUn
    | Clt
    | CltUn
    | Ldftn of MetadataToken
    | Ldvirtftn of MetadataToken
    | Localloc
    | Endfilter
    | Initobj of MetadataToken
    | Cpblk
    | Initblk of byte option
    | Rethrow
    | Sizeof of MetadataToken
    | Refanytype

// TODO not sure if using int64 is a good choice here. Maybe use uint32 and check
// before reading instead of checking for negative after
let readInsts (r : BinaryReader) (codeSize : uint32) =
    let currOffset = ref 0u

    // convenience functions for reading bytes
    let readByte () =
        currOffset := !currOffset + 1u
        r.ReadByte ()

    let readSByte () =
        currOffset := !currOffset + 1u
        r.ReadSByte ()

    let readInt16 () =
        currOffset := !currOffset + 2u
        r.ReadInt16 ()

    let readUInt16 () =
        currOffset := !currOffset + 2u
        r.ReadUInt16 ()

    let readInt32 () =
        currOffset := !currOffset + 4u
        r.ReadInt32 ()

    let readUInt32 () =
        currOffset := !currOffset + 4u
        r.ReadUInt32 ()

    let readInt64 () =
        currOffset := !currOffset + 8u
        r.ReadInt64 ()

    let readUInt64 () =
        currOffset := !currOffset + 8u
        r.ReadUInt64 ()

    let readSingle () =
        currOffset := !currOffset + 4u
        r.ReadSingle ()

    let readDouble () =
        currOffset := !currOffset + 8u
        r.ReadDouble ()

    let readMetaTok () =
        currOffset := !currOffset + 4u
        readMetadataToken r

    let rec readInst
            (constrainedPrefix : MetadataToken option)
            (noPrefix : byte)
            (readonlyPrefix : bool) // TODO figure out what to do w/ readonly
            (tailPrefix : bool)
            (unalignedPrefix : byte option)
            (volatilePrefix : bool) =
        match readByte () with
        | 0x00uy -> RawInst.Nop
        | 0x01uy -> RawInst.Break
        | 0x02uy -> RawInst.Ldarg 0us
        | 0x03uy -> RawInst.Ldarg 1us
        | 0x04uy -> RawInst.Ldarg 2us
        | 0x05uy -> RawInst.Ldarg 3us
        | 0x06uy -> RawInst.Ldloc 0us
        | 0x07uy -> RawInst.Ldloc 1us
        | 0x08uy -> RawInst.Ldloc 2us
        | 0x09uy -> RawInst.Ldloc 3us
        | 0x0Auy -> RawInst.Stloc 0us
        | 0x0Buy -> RawInst.Stloc 1us
        | 0x0Cuy -> RawInst.Stloc 2us
        | 0x0Duy -> RawInst.Stloc 3us
        | 0x0Euy -> RawInst.Ldarg (readByte () |> uint16)
        | 0x0Fuy -> RawInst.Ldarga (readByte () |> uint16)
        | 0x10uy -> RawInst.Starg (readByte () |> uint16)
        | 0x11uy -> RawInst.Ldloc (readByte () |> uint16)
        | 0x12uy -> RawInst.Ldloca (readByte () |> uint16)
        | 0x13uy -> RawInst.Stloc (readByte () |> uint16)
        | 0x14uy -> RawInst.Ldnull
        | 0x15uy -> RawInst.LdcI4 -1
        | 0x16uy -> RawInst.LdcI4 0
        | 0x17uy -> RawInst.LdcI4 1
        | 0x18uy -> RawInst.LdcI4 2
        | 0x19uy -> RawInst.LdcI4 3
        | 0x1Auy -> RawInst.LdcI4 4
        | 0x1Buy -> RawInst.LdcI4 5
        | 0x1Cuy -> RawInst.LdcI4 6
        | 0x1Duy -> RawInst.LdcI4 7
        | 0x1Euy -> RawInst.LdcI4 8
        | 0x1Fuy -> RawInst.LdcI4 (readSByte () |> int) // TODO will this do the right thing for -1y
        | 0x20uy -> RawInst.LdcI4 (readInt32 ())
        | 0x21uy -> RawInst.LdcI8 (readInt64 ())
        | 0x22uy -> RawInst.LdcR4 (readSingle ())
        | 0x23uy -> RawInst.LdcR8 (readDouble ())
        | 0x25uy -> RawInst.Dup
        | 0x26uy -> RawInst.Pop
        | 0x27uy -> RawInst.Jmp (readMetaTok ())
        | 0x28uy -> RawInst.Call (tailPrefix, readMetaTok ())
        | 0x29uy -> RawInst.Calli (tailPrefix, readMetaTok ())
        | 0x2Auy -> RawInst.Ret
        | 0x2Buy -> RawInst.Br (readSByte () |> int)
        | 0x2Cuy -> RawInst.Brfalse (readSByte () |> int)
        | 0x2Duy -> RawInst.Brtrue (readSByte () |> int)
        | 0x2Euy -> RawInst.Beq (readSByte () |> int)
        | 0x2Fuy -> RawInst.Bge (readSByte () |> int)
        | 0x30uy -> RawInst.Bgt (readSByte () |> int)
        | 0x31uy -> RawInst.Ble (readSByte () |> int)
        | 0x32uy -> RawInst.Blt (readSByte () |> int)
        | 0x33uy -> RawInst.BneUn (readSByte () |> int)
        | 0x34uy -> RawInst.BgeUn (readSByte () |> int)
        | 0x35uy -> RawInst.BgtUn (readSByte () |> int)
        | 0x36uy -> RawInst.BleUn (readSByte () |> int)
        | 0x37uy -> RawInst.BltUn (readSByte () |> int)
        | 0x38uy -> RawInst.Br (readInt32 ())
        | 0x39uy -> RawInst.Brfalse (readInt32 ())
        | 0x3Auy -> RawInst.Brtrue (readInt32 ())
        | 0x3Buy -> RawInst.Beq (readInt32 ())
        | 0x3Cuy -> RawInst.Bge (readInt32 ())
        | 0x3Duy -> RawInst.Bgt (readInt32 ())
        | 0x3Euy -> RawInst.Ble (readInt32 ())
        | 0x3Fuy -> RawInst.Blt (readInt32 ())
        | 0x40uy -> RawInst.BneUn (readInt32 ())
        | 0x41uy -> RawInst.BgeUn (readInt32 ())
        | 0x42uy -> RawInst.BgtUn (readInt32 ())
        | 0x43uy -> RawInst.BleUn (readInt32 ())
        | 0x44uy -> RawInst.BltUn (readInt32 ())
        | 0x45uy -> RawInst.Switch [|for _ in 1u .. readUInt32 () -> readInt32 ()|]
        | 0x47uy -> RawInst.LdindU1 unalignedPrefix
        | 0x48uy -> RawInst.LdindI2 unalignedPrefix
        | 0x49uy -> RawInst.LdindU2 unalignedPrefix
        | 0x4Auy -> RawInst.LdindI4 unalignedPrefix
        | 0x4Buy -> RawInst.LdindU4 unalignedPrefix
        | 0x4Cuy -> RawInst.LdindI8 unalignedPrefix
        | 0x4Duy -> RawInst.LdindI unalignedPrefix
        | 0x4Euy -> RawInst.LdindR4 unalignedPrefix
        | 0x4Fuy -> RawInst.LdindR8 unalignedPrefix
        | 0x50uy -> RawInst.LdindRef unalignedPrefix
        | 0x51uy -> RawInst.StindRef unalignedPrefix
        | 0x52uy -> RawInst.StindI1 unalignedPrefix
        | 0x53uy -> RawInst.StindI2 unalignedPrefix
        | 0x54uy -> RawInst.StindI4 unalignedPrefix
        | 0x55uy -> RawInst.StindI8 unalignedPrefix
        | 0x56uy -> RawInst.StindR4 unalignedPrefix
        | 0x57uy -> RawInst.StindR8 unalignedPrefix
        | 0x58uy -> RawInst.Add
        | 0x59uy -> RawInst.Sub
        | 0x5Auy -> RawInst.Mul
        | 0x5Buy -> RawInst.Div
        | 0x5Cuy -> RawInst.DivUn
        | 0x5Duy -> RawInst.Rem
        | 0x5Euy -> RawInst.RemUn
        | 0x5Fuy -> RawInst.And
        | 0x60uy -> RawInst.Or
        | 0x61uy -> RawInst.Xor
        | 0x62uy -> RawInst.Shl
        | 0x63uy -> RawInst.Shr
        | 0x64uy -> RawInst.ShrUn
        | 0x65uy -> RawInst.Neg
        | 0x66uy -> RawInst.Not
        | 0x67uy -> RawInst.ConvI1
        | 0x68uy -> RawInst.ConvI2
        | 0x69uy -> RawInst.ConvI4
        | 0x6Auy -> RawInst.ConvI8
        | 0x6Buy -> RawInst.ConvR4
        | 0x6Cuy -> RawInst.ConvR8
        | 0x6Duy -> RawInst.ConvU4
        | 0x6Euy -> RawInst.ConvU8
        | 0x6Fuy -> RawInst.Callvirt (constrainedPrefix, tailPrefix, readMetaTok ())
        | 0x70uy -> RawInst.Cpobj (readMetaTok ())
        | 0x71uy -> RawInst.Ldobj (unalignedPrefix, readMetaTok ())
        | 0x72uy -> RawInst.Ldstr (readMetaTok ())
        | 0x73uy -> RawInst.Newobj (readMetaTok ())
        | 0x74uy -> RawInst.Castclass (readMetaTok ())
        | 0x75uy -> RawInst.Isinst (readMetaTok ())
        | 0x76uy -> RawInst.ConvRUn
        | 0x79uy -> RawInst.Unbox (readMetaTok ())
        | 0x7Auy -> RawInst.Throw
        | 0x7Buy -> RawInst.Ldfld (unalignedPrefix, readMetaTok ())
        | 0x7Cuy -> RawInst.Ldflda (unalignedPrefix, readMetaTok ())
        | 0x7Duy -> RawInst.Stfld (unalignedPrefix, readMetaTok ())
        | 0x7Euy -> RawInst.Ldsfld (readMetaTok ())
        | 0x7Fuy -> RawInst.Ldsflda (readMetaTok ())
        | 0x80uy -> RawInst.Stsfld (readMetaTok ())
        | 0x81uy -> RawInst.Stobj (unalignedPrefix, readMetaTok ())
        | 0x82uy -> RawInst.ConvOvfI1Un
        | 0x83uy -> RawInst.ConvOvfI2Un
        | 0x84uy -> RawInst.ConvOvfI4Un
        | 0x85uy -> RawInst.ConvOvfI8Un
        | 0x86uy -> RawInst.ConvOvfU1Un
        | 0x87uy -> RawInst.ConvOvfU2Un
        | 0x88uy -> RawInst.ConvOvfU4Un
        | 0x89uy -> RawInst.ConvOvfU8Un
        | 0x8Auy -> RawInst.ConvOvfIUn
        | 0x8Buy -> RawInst.ConvOvfUUn
        | 0x8Cuy -> RawInst.Box (readMetaTok ())
        | 0x8Duy -> RawInst.Newarr (readMetaTok ())
        | 0x8Euy -> RawInst.Ldlen
        | 0x8Fuy -> RawInst.Ldelema (readMetaTok ())
        | 0x90uy -> RawInst.LdelemI1
        | 0x91uy -> RawInst.LdelemU1
        | 0x92uy -> RawInst.LdelemI2
        | 0x93uy -> RawInst.LdelemU2
        | 0x94uy -> RawInst.LdelemI4
        | 0x95uy -> RawInst.LdelemU4
        | 0x96uy -> RawInst.LdelemI8
        | 0x97uy -> RawInst.LdelemI
        | 0x98uy -> RawInst.LdelemR4
        | 0x99uy -> RawInst.LdelemR8
        | 0x9Auy -> RawInst.LdelemRef
        | 0x9Buy -> RawInst.StelemI
        | 0x9Cuy -> RawInst.StelemI1
        | 0x9Duy -> RawInst.StelemI2
        | 0x9Euy -> RawInst.StelemI4
        | 0x9Fuy -> RawInst.StelemI8
        | 0xA0uy -> RawInst.StelemR4
        | 0xA1uy -> RawInst.StelemR8
        | 0xA2uy -> RawInst.StelemRef
        | 0xA3uy -> RawInst.Ldelem (readMetaTok ())
        | 0xA4uy -> RawInst.Stelem (readMetaTok ())
        | 0xA5uy -> RawInst.UnboxAny (readMetaTok ())
        | 0xB3uy -> RawInst.ConvOvfI1
        | 0xB4uy -> RawInst.ConvOvfU1
        | 0xB5uy -> RawInst.ConvOvfI2
        | 0xB6uy -> RawInst.ConvOvfU2
        | 0xB7uy -> RawInst.ConvOvfI4
        | 0xB8uy -> RawInst.ConvOvfU4
        | 0xB9uy -> RawInst.ConvOvfI8
        | 0xBAuy -> RawInst.ConvOvfU8
        | 0xC2uy -> RawInst.Refanyval (readMetaTok ())
        | 0xC3uy -> RawInst.Ckfinite
        | 0xC6uy -> RawInst.Mkrefany (readMetaTok ())
        | 0xD0uy -> RawInst.Ldtoken (readMetaTok ())
        | 0xD1uy -> RawInst.ConvU2
        | 0xD2uy -> RawInst.ConvU1
        | 0xD3uy -> RawInst.ConvI
        | 0xD4uy -> RawInst.ConvOvfI
        | 0xD5uy -> RawInst.ConvOvfU
        | 0xD6uy -> RawInst.AddOvf
        | 0xD7uy -> RawInst.AddOvfUn
        | 0xD8uy -> RawInst.MulOvf
        | 0xD9uy -> RawInst.MulOvfUn
        | 0xDAuy -> RawInst.SubOvf
        | 0xDBuy -> RawInst.SubOvfUn
        | 0xDCuy -> RawInst.Endfinally
        | 0xDDuy -> RawInst.Leave (readInt32 ())
        | 0xDEuy -> RawInst.Leave (readSByte () |> int)
        | 0xDFuy -> RawInst.StindI unalignedPrefix
        | 0xE0uy -> RawInst.ConvU
        | 0xFEuy ->
            match readByte () with
            | 0x00uy -> RawInst.Arglist
            | 0x01uy -> RawInst.Ceq
            | 0x02uy -> RawInst.Cgt
            | 0x03uy -> RawInst.CgtUn
            | 0x04uy -> RawInst.Clt
            | 0x05uy -> RawInst.CltUn
            | 0x06uy -> RawInst.Ldftn (readMetaTok ())
            | 0x07uy -> RawInst.Ldvirtftn (readMetaTok ())
            | 0x09uy -> RawInst.Ldarg (readUInt16 ())
            | 0x0Auy -> RawInst.Ldarga (readUInt16 ())
            | 0x0Buy -> RawInst.Starg (readUInt16 ())
            | 0x0Cuy -> RawInst.Ldloc (readUInt16 ())
            | 0x0Duy -> RawInst.Ldloca (readUInt16 ())
            | 0x0Euy -> RawInst.Stloc (readUInt16 ())
            | 0x0Fuy -> RawInst.Localloc
            | 0x11uy -> RawInst.Endfilter
            | 0x12uy ->
                match unalignedPrefix with
                | Some _ -> failwith "repeated unaligned. prefixes"
                | None ->
                    let alignVal = readByte ()
                    readInst constrainedPrefix noPrefix readonlyPrefix tailPrefix (Some alignVal) volatilePrefix
            | 0x13uy ->
                if volatilePrefix then
                    failwith "repeated volatile. prefixes"
                else
                    readInst constrainedPrefix noPrefix readonlyPrefix tailPrefix unalignedPrefix true
            | 0x14uy ->
                if tailPrefix then
                    failwith "repeated tail. prefixes"
                else
                    readInst constrainedPrefix noPrefix readonlyPrefix true unalignedPrefix volatilePrefix
            | 0x15uy -> RawInst.Initobj (readMetaTok ())
            | 0x16uy ->
                match constrainedPrefix with
                | Some _ -> failwith "repeated constrained. prefixes"
                | None ->
                    let constrainedTok = Some (readMetaTok ())
                    readInst constrainedTok noPrefix readonlyPrefix tailPrefix unalignedPrefix volatilePrefix
            | 0x17uy -> RawInst.Cpblk
            | 0x18uy -> RawInst.Initblk unalignedPrefix
            | 0x19uy ->
                // TODO is it worth doing anything with this?
                let currNo = readByte ()
                readInst constrainedPrefix (noPrefix ||| currNo) readonlyPrefix tailPrefix unalignedPrefix volatilePrefix
            | 0x1Auy -> RawInst.Rethrow
            | 0x1Cuy -> RawInst.Sizeof (readMetaTok ())
            | 0x1Duy -> RawInst.Refanytype
            | 0x1Euy ->
                if readonlyPrefix then
                    failwith "repeated readonly. prefixes"
                else
                    readInst constrainedPrefix noPrefix true tailPrefix unalignedPrefix volatilePrefix
            | bc -> failwithf "unknown bytecode 0xFE 0x%X" bc
        
        | bc -> failwithf "unknown bytecode 0x%X" bc

    [|while !currOffset < codeSize do
        // yield the instruction along with the amount of space that the instruction takes
        let instOffset = !currOffset
        let inst = readInst None 0uy false false None false
        let instSize = !currOffset - instOffset
        yield (inst, instSize)|]

type TryAndHandler = {
    tryOffsetLen : uint32 * uint32
    handlerOffsetLen : uint32 * uint32}

type ExceptionClause =
    | TypedException of TryAndHandler * MetadataToken
    | Finally of TryAndHandler * MetadataToken // TODO do we really need MetadataToken here?
    | Fault of TryAndHandler * MetadataToken // TODO do we really need MetadataToken here?

    // Section 12.4.2.7: If an exception entry contains a filterstart, then
    // filterstart strictly precedes handlerstart. The filter starts at the
    // instruction specified by filterstart and contains all instructions up to
    // (but not including) that specified by handlerstart. The lexically last
    // instruction in the filter must be endfilter. If there is no filterstart
    // then the filter is empty (hence it does not overlap with any region).
    | Filter of TryAndHandler * uint32

let toExceptionClause
        (eFlags : uint32)
        (tryOffset : uint32)
        (tryLen : uint32)
        (handlerOffset : uint32)
        (handlerLen : uint32)
        (offsetOrClassTok : uint32) =

    let tryAndHdlr = {
        tryOffsetLen = tryOffset, tryLen
        handlerOffsetLen = handlerOffset, handlerLen}
    match eFlags with
    | 0x0000u -> TypedException (tryAndHdlr, toMetadataToken offsetOrClassTok)
    | 0x0001u -> Filter (tryAndHdlr, offsetOrClassTok)
    | 0x0002u -> Finally (tryAndHdlr, toMetadataToken offsetOrClassTok)
    | 0x0004u -> Fault (tryAndHdlr, toMetadataToken offsetOrClassTok)
    | _ -> failwithf "bad exception clause kind 0x%X" eFlags

let readFatExceptionClauses (r : BinaryReader) =
    // Section 25.4.3
    let dataSize =
        match r.ReadBytes 3 with
        | [|b1; b2; b3|] ->
            // these are little-endian, so little bytes first
            uint32 b1 ||| (uint32 b2 <<< 8) ||| (uint32 b3 <<< 16)
        | _ ->
            failwith "unexpected end of file while reading data section"
    let numClauses = (dataSize - 4u) / 24u

    if (numClauses * 24u) + 4u <> dataSize then
        failwithf "bad dataSize in fat section: %i" dataSize
    
    // See 25.4.6 reading fat clauses
    [|for _ in 1u .. numClauses do
        debugfn "reading fat clause"
        let eFlags = r.ReadUInt32 ()
        let tryOffset = r.ReadUInt32 ()
        let tryLen = r.ReadUInt32 ()
        let handlerOffset = r.ReadUInt32 ()
        let handlerLen = r.ReadUInt32 ()
        let offsetOrClassTok = r.ReadUInt32 ()

        debugfn
            "eFlags=0x%X, tryOffset=%i, tryLen=%i, handlerOffset=%i, handlerLen=%i, offsetOrClassTok=%i"
            eFlags
            tryOffset
            tryLen
            handlerOffset
            handlerLen
            offsetOrClassTok

        yield toExceptionClause eFlags tryOffset tryLen handlerOffset handlerLen offsetOrClassTok|]

let readSmallExceptionClauses (r : BinaryReader) =
    // Section 25.4.2
    let dataSize = r.ReadByte ()
    let numClauses = (dataSize - 4uy) / 12uy
    readShortEq r 0us "small method header reserved"
    
    if (numClauses * 12uy) + 4uy <> dataSize then
        failwithf "bad dataSize in small section: %i" dataSize
    
    // See 25.4.6 reading small clauses
    [|for _ in 1uy .. numClauses do
        debugfn "reading small clause"
        let eFlags = r.ReadUInt16 () |> uint32
        let tryOffset = r.ReadUInt16 () |> uint32
        let tryLen = r.ReadByte () |> uint32
        let handlerOffset = r.ReadUInt16 () |> uint32
        let handlerLen = r.ReadByte () |> uint32
        let offsetOrClassTok = r.ReadUInt32 ()

        debugfn
            "eFlags=0x%X, tryOffset=%i, tryLen=%i, handlerOffset=%i, handlerLen=%i, offsetOrClassTok=%i"
            eFlags
            tryOffset
            tryLen
            handlerOffset
            handlerLen
            offsetOrClassTok

        yield toExceptionClause eFlags tryOffset tryLen handlerOffset handlerLen offsetOrClassTok|]

let readExceptionSections (r : BinaryReader) (moreSects : bool) (codeSize : uint32) =
    let moreSects = ref moreSects
    [|while !moreSects do
        debugfn "reading exception section"
        
        // the method data sits on a 4-byte boundary. Seek past
        // boundary bytes
        let codeRem = codeSize % 4u
        if codeRem <> 0u then
            let seekDist = 4L - int64 codeRem
            r.BaseStream.Seek (seekDist, SeekOrigin.Current) |> ignore

        let kindFlags = r.ReadByte ()
        let isException = kindFlags &&& 0x01uy <> 0uy
        if not isException then
            failwith "expected exception flag to be set"
        let optILTable = kindFlags &&& 0x02uy <> 0uy
        if optILTable then
            failwith "expected optILTable flag to be unset"
        let isFatFormat = kindFlags &&& 0x40uy <> 0uy
        moreSects := kindFlags &&& 0x80uy <> 0uy

        debugfn "exception is fat: %b" isFatFormat

        if isFatFormat then
            yield readFatExceptionClauses r
        else
            yield readSmallExceptionClauses r|]

// Defined in Section 25.4
let readMethodBody (r : BinaryReader) =
    let fstByte = r.ReadByte ()

    let isTinyFmt =
        match fstByte &&& 0x03uy with
        | 0x02uy -> true
        | 0x03uy -> false
        | n -> failwithf "bad method body format 0x%X" n

    if isTinyFmt then
        let mbSize = fstByte >>> 2
        debugfn "tiny header: size=%i" mbSize

        readInsts r (uint32 mbSize), [||]
    else
        let moreSects = fstByte &&& 0x08uy <> 0uy
        let initLocals = fstByte &&& 0x10uy <> 0uy
        let headerSize = r.ReadByte () >>> 4
        if headerSize <> 3uy then
            failwith "expected method body header size to be 3 but it's %i" headerSize
        let maxStack = r.ReadUInt16 ()
        let codeSize = r.ReadUInt32 ()
        let localVarSigTok = r.ReadUInt32 ()

        debugfn
            "fat header: moreSects=%b, initLocals=%b, headerSize=%i, maxStack=%i, codeSize=%i, localVarSigTok=%i"
            moreSects
            initLocals
            headerSize
            maxStack
            codeSize
            localVarSigTok

        let insts = readInsts r codeSize
        let exceptionSecs = readExceptionSections r moreSects codeSize

        insts, exceptionSecs
