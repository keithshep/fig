module Fig.CecilExt

open Mono.Cecil
open Mono.Cecil.Cil
open Mono.Cecil.Rocks

let failwithf fmt = Printf.ksprintf failwith fmt

let rec splitAt i xs =
    if i = 0 then
        ([], xs)
    else
        match xs with
        | [] -> failwith "not enough elements for split"
        | x :: xt ->
            let splitFst, splitSnd = splitAt (i - 1) xt
            (x :: splitFst, splitSnd)

/// for keeping track of what types will be on the stack
/// See EMCA 335: Partition VI C.2, Partition III 1.5, Partition III 1.1
type StackType =
    | Int32
    | Int64
    | NativeInt
    | Float
    | ObjectRef
    | ManagedPointer

/// a safer type reference
type SaferTypeRef =
    | Void
    | Boolean
    | Char
    | SByte
    | Byte
    | Int16
    | UInt16
    | Int32
    | UInt32
    | Int64
    | UInt64
    | Single
    | Double
    | String
    | Pointer of PointerType
    | ByReference of ByReferenceType
    | ValueType of TypeReference
    | Class of TypeReference
    | Var of GenericParameter
    | Array of ArrayType
    | GenericInstance of GenericInstanceType
    | TypedByReference
    | IntPtr
    | UIntPtr
    | FunctionPointer of FunctionPointerType
    | Object
    | MVar of GenericParameter
    | RequiredModifier of RequiredModifierType
    | OptionalModifier of OptionalModifierType
    | Sentinel of SentinelType
    | Pinned of PinnedType

/// converts a standard cecil TypeReference object into one of our
/// SaferTypeRef discriminated unions
/// See Section II: 23.1.16 Element types used in signatures
let toSaferType (ty : TypeReference) =
    match ty.MetadataType with
    | MetadataType.Void             -> Void
    | MetadataType.Boolean          -> Boolean
    | MetadataType.Char             -> Char
    | MetadataType.SByte            -> SByte
    | MetadataType.Byte             -> Byte
    | MetadataType.Int16            -> Int16
    | MetadataType.UInt16           -> UInt16
    | MetadataType.Int32            -> Int32
    | MetadataType.UInt32           -> UInt32
    | MetadataType.Int64            -> Int64
    | MetadataType.UInt64           -> UInt64
    | MetadataType.Single           -> Single
    | MetadataType.Double           -> Double
    | MetadataType.String           -> String
    | MetadataType.Pointer          -> Pointer (ty :?> PointerType)
    | MetadataType.ByReference      -> ByReference (ty :?> ByReferenceType)
    | MetadataType.ValueType        -> ValueType ty
    | MetadataType.Class            -> Class ty
    | MetadataType.Var              -> Var (ty :?> GenericParameter)
    | MetadataType.Array            -> Array (ty :?> ArrayType)
    | MetadataType.GenericInstance  -> GenericInstance (ty :?> GenericInstanceType)
    | MetadataType.TypedByReference -> TypedByReference
    | MetadataType.IntPtr           -> IntPtr
    | MetadataType.UIntPtr          -> UIntPtr
    | MetadataType.FunctionPointer  -> FunctionPointer (ty :?> FunctionPointerType)
    | MetadataType.Object           -> Object
    | MetadataType.MVar             -> MVar (ty :?> GenericParameter)
    | MetadataType.RequiredModifier -> RequiredModifier (ty :?> RequiredModifierType)
    | MetadataType.OptionalModifier -> OptionalModifier (ty :?> OptionalModifierType)
    | MetadataType.Sentinel         -> Sentinel (ty :?> SentinelType)
    | MetadataType.Pinned           -> Pinned (ty :?> PinnedType)
    | _ ->
        failwithf "unexpected MetadataType: %A" ty.MetadataType

/// see Partition I: 8.7
let asIntermediateType (t : TypeReference) =

    let t = toSaferType t
    
    let iHaveNoClue () =
        failwithf "I have no clue what to do with %A" t
    
    let fromManagedPtr (ptrType : TypeSpecification) =
        let pointeeType = toSaferType ptrType.ElementType
        match pointeeType with
        | Boolean | Char | SByte | Byte | Int16 | UInt16 | Int32 | UInt32 ->
            StackType.Int32
        | Int64 | UInt64 ->
            StackType.Int64
        | Single | Double ->
            StackType.Float
        | IntPtr | UIntPtr ->
            StackType.NativeInt
        | _ ->
            StackType.ManagedPointer

    match t with
    | Void ->
        failwith "no stack type corresponding to void"
    | Pointer ptrType ->
        fromManagedPtr ptrType
    | Boolean | Char | SByte | Byte | Int16 | UInt16 | Int32 | UInt32 ->
        StackType.Int32
    | Int64 | UInt64 ->
        StackType.Int64
    | Single | Double ->
        StackType.Float
    | IntPtr | UIntPtr ->
        StackType.NativeInt
    | Object | String ->
        StackType.ObjectRef
    | ByReference _ ->
        StackType.ManagedPointer
    | ValueType _ ->
        // TODO I think this is probably completely bogus
        StackType.ObjectRef
    | Class _ ->
        // TODO understand difference between object and class
        // I think Object means the base object type
        StackType.ObjectRef
    | Var _ ->
        iHaveNoClue ()
    | Array _ ->
        StackType.ObjectRef
    | GenericInstance _ ->
        iHaveNoClue ()
    | TypedByReference ->
        iHaveNoClue ()
    | FunctionPointer _ ->
        iHaveNoClue ()
    | MVar _ ->
        iHaveNoClue ()
    | RequiredModifier _ ->
        iHaveNoClue ()
    | OptionalModifier _ ->
        iHaveNoClue ()
    | Sentinel _ ->
        iHaveNoClue ()
    | Pinned _ ->
        iHaveNoClue ()

/// a basic block is always entered by the first instruction and
/// exited by the last instruction
type BasicBlock (offsetBytes : int) =
    let mutable initStackTypes = [] : StackType list
    let mutable instructions = [] : AnnotatedInstruction list
    
    /// the the types of the variables that should be on the stack when this
    /// block is run
    member x.InitStackTypes
        with get () = initStackTypes
        and set tys = initStackTypes <- tys

    /// the instructions in this code block
    member x.Instructions
        with get () = instructions
        and set insts = instructions <- insts
    
    /// the offset in bytes is relative to the function body so it acts
    /// as a unique ID for a given block in a function
    member x.OffsetBytes = offsetBytes

    /// determines all possible successors to this basic block
    member x.Successors =
        match instructions.[instructions.Length - 1].Instruction with
        | Beq (ifBB, elseBB) | Bge (ifBB, elseBB) | Bgt (ifBB, elseBB)
        | Ble (ifBB, elseBB) | Blt (ifBB, elseBB) | BneUn (ifBB, elseBB)
        | BgeUn (ifBB, elseBB) | BgtUn (ifBB, elseBB) | BleUn (ifBB, elseBB)
        | BltUn (ifBB, elseBB) | Brfalse (ifBB, elseBB) | Brtrue (ifBB, elseBB) ->
            [ifBB; elseBB]
        | Br bb | Leave bb ->
            [bb]
        | Switch (caseBBs, fallthroughBB) ->
            fallthroughBB :: List.ofArray caseBBs
        | _ ->
            []

/// A typesafe and simplified view of cecil's Instruction class
/// See: ECMA-335 Partition III
and SaferInstruction =
    | Add
    | And
    | Beq of BasicBlock * BasicBlock
    | Bge of BasicBlock * BasicBlock
    | Bgt of BasicBlock * BasicBlock
    | Ble of BasicBlock * BasicBlock
    | Blt of BasicBlock * BasicBlock
    | BneUn of BasicBlock * BasicBlock
    | BgeUn of BasicBlock * BasicBlock
    | BgtUn of BasicBlock * BasicBlock
    | BleUn of BasicBlock * BasicBlock
    | BltUn of BasicBlock * BasicBlock
    | Br of BasicBlock
    | Break
    | Brfalse of BasicBlock * BasicBlock
    | Brtrue of BasicBlock * BasicBlock
    
    // call* instructions all start with bool "tail." prefix indicator.
    // See: EMCA-335 Partition III 2.4
    | Call of bool * MethodReference
    | Calli of bool * CallSite
    
    // callvirt can also take a "constrained." prefix
    // See: EMCA-335 Partition III 2.1
    | Callvirt of bool * TypeReference option * MethodReference
    | ConvI1
    | ConvI2
    | ConvI4
    | ConvI8
    | ConvR4
    | ConvR8
    | ConvU4
    | ConvU8
    | Cpobj of TypeReference
    | Div
    | DivUn
    | Dup
    | Jmp of MethodReference
    | Ldarg of ParameterDefinition
    | Ldarga of ParameterDefinition
    | LdcI4 of int
    | LdcI8 of int64
    | LdcR4 of single
    | LdcR8 of double
    
    // ldind* instructions hold a byte option for the "unaligned." prefix
    // and a bool for the "volatile." prefix
    // See: EMCA-335 Partition III 2.5 & 2.6
    | LdindI1 of byte option * bool
    | LdindU1 of byte option * bool
    | LdindI2 of byte option * bool
    | LdindU2 of byte option * bool
    | LdindI4 of byte option * bool
    | LdindU4 of byte option * bool
    | LdindI8 of byte option * bool
    | LdindI of byte option * bool
    | LdindR4 of byte option * bool
    | LdindR8 of byte option * bool
    | LdindRef of byte option * bool
    | Ldloc of VariableDefinition
    | Ldloca of VariableDefinition
    | Ldnull

    // Ldobj instruction hold a byte option for the "unaligned." prefix
    // and a bool for the "volatile." prefix
    // See: EMCA-335 Partition III 2.5 & 2.6
    | Ldobj of byte option * bool * TypeReference
    | Ldstr of string
    | Mul
    | Neg
    | Nop
    | Not
    | Newobj of MethodReference
    | Or
    | Pop
    | Rem
    | RemUn
    | Ret
    | Shl
    | Shr
    | ShrUn
    | Starg of ParameterDefinition
    
    // Stind* instructions hold a byte option for the "unaligned." prefix
    // and a bool for the "volatile." prefix
    // See: EMCA-335 Partition III 2.5 & 2.6
    | StindRef of byte option * bool
    | StindI1 of byte option * bool
    | StindI2 of byte option * bool
    | StindI4 of byte option * bool
    | StindI8 of byte option * bool
    | StindR4 of byte option * bool
    | StindR8 of byte option * bool
    | Stloc of VariableDefinition
    | Sub
    | Switch of BasicBlock array * BasicBlock
    | Xor
    | Castclass of TypeReference
    | Isinst of TypeReference
    | ConvRUn
    | Unbox of TypeReference
    | Throw

    // ldfld*/stfld instructions hold a byte option for the "unaligned." prefix
    // and a bool for the "volatile." prefix
    // See: EMCA-335 Partition III 2.5 & 2.6
    | Ldfld of byte option * bool * FieldReference
    | Ldflda of byte option * bool * FieldReference
    | Stfld of byte option * bool * FieldReference
    
    // ldsfld*/stsfld instructions hold a bool indicator for the "volatile." prefix
    | Ldsfld of bool * FieldReference
    | Ldsflda of bool * FieldReference
    | Stsfld of bool * FieldReference
    
    // stobj instruction holds a byte option for the "unaligned." prefix
    // and a bool for the "volatile." prefix
    // See: EMCA-335 Partition III 2.5 & 2.6
    | Stobj of byte option * bool * TypeReference
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
    | Box of TypeReference
    | Newarr of TypeReference
    | Ldlen
    
    // ldelema instruction holds a bool to indicate that it is preceded by a
    // "readonly." prefix
    // See: EMCA-335 Partition III 2.3
    | Ldelema of bool * TypeReference
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
    | Ldelem of TypeReference
    | Stelem of TypeReference
    | UnboxAny of TypeReference
    | ConvOvfI1
    | ConvOvfU1
    | ConvOvfI2
    | ConvOvfU2
    | ConvOvfI4
    | ConvOvfU4
    | ConvOvfI8
    | ConvOvfU8
    | Refanyval of TypeReference
    | Ckfinite
    | Mkrefany of TypeReference
    | Ldtoken of IMetadataTokenProvider
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
    | Leave of BasicBlock

    // stindi instructions hold a byte option for the "unaligned." prefix
    // and a bool for the "volatile." prefix
    // See: EMCA-335 Partition III 2.5 & 2.6
    | StindI of byte option * bool
    | ConvU
    | Arglist
    | Ceq
    | Cgt
    | CgtUn
    | Clt
    | CltUn
    | Ldftn of MethodReference
    | Ldvirtftn of MethodReference
    | Localloc
    | Endfilter
    | Initobj of TypeReference
    | Cpblk

    // initblk instructions hold a byte option for the "unaligned." prefix
    // and a bool for the "volatile." prefix
    // See: EMCA-335 Partition III 2.5 & 2.6
    | Initblk of byte option * bool
    | Rethrow
    | Sizeof of TypeReference
    | Refanytype

and AnnotatedInstruction (inst : SaferInstruction, popB : StackBehaviour, pushB : StackBehaviour, flowControl : FlowControl) =

    let popTypes (stackTypes : StackType list) =
        match popB with
        | StackBehaviour.Pop0 ->
            ([], stackTypes)
        | StackBehaviour.Pop1
        | StackBehaviour.Popi
        | StackBehaviour.Popref ->
            match stackTypes with
            | a :: stackTail -> ([a], stackTail)
            | [] -> failwith "unexpected empty stack"
        | StackBehaviour.Pop1_pop1
        | StackBehaviour.Popi_pop1
        | StackBehaviour.Popi_popi
        | StackBehaviour.Popi_popi8
        | StackBehaviour.Popi_popr4
        | StackBehaviour.Popi_popr8
        | StackBehaviour.Popref_pop1
        | StackBehaviour.Popref_popi ->
            match stackTypes with
            | a :: b :: stackTail -> ([a; b], stackTail)
            | _ -> failwith "expected at least two items in the stack"
        | StackBehaviour.Popi_popi_popi
        | StackBehaviour.Popref_popi_popi
        | StackBehaviour.Popref_popi_popi8
        | StackBehaviour.Popref_popi_popr4
        | StackBehaviour.Popref_popi_popr8
        | StackBehaviour.Popref_popi_popref ->
            match stackTypes with
            | a :: b :: c :: stackTail -> ([a; b; c], stackTail)
            | _ -> failwith "expected at least three items in the stack"
        | StackBehaviour.PopAll ->
            (stackTypes, [])
        | StackBehaviour.Varpop ->
            let methSigPopCount (methSig : IMethodSignature) =
                let paramLen = methSig.Parameters.Count
                if methSig.HasThis then
                    paramLen + 1
                else
                    paramLen

            let popCount =
                match inst with
                | Call (_, methRef)
                | Callvirt (_, _, methRef) ->
                    methSigPopCount methRef
                | Newobj methRef ->
                    // TODO double check the - 1 here
                    methSigPopCount methRef - 1
                | Calli (_, callSite) ->
                    methSigPopCount callSite
                | Ret ->
                    match stackTypes with
                    | [] -> 0
                    | [_] -> 1
                    | _ -> failwith "a ret instruction should only have 0 or 1 items on the stack"
                | _ ->
                    failwithf "unexpected variable pop for instruction: %A" inst

            splitAt popCount stackTypes

        | _ ->
            failwithf "unexpected pop behavior %A" popB

    member x.FlowControl = flowControl

    member x.Instruction = inst
    
    /// update the type stack
    member x.UpdateTypes (stackTypes : StackType list) =

        let poppedTypes, stackTail = popTypes stackTypes

        let badStack () = failwithf "bad stack types for %A" inst

        match inst with
        | Add | Div | Mul | Rem | Sub ->

            // binary numeric operations defined in
            // Partition III 1.5
            // TODO: assuming valid bytecode here
            match poppedTypes with
            | [StackType.Int32; StackType.Int32] ->
                StackType.Int32 :: stackTail
            | [StackType.Float; StackType.Float] ->
                StackType.Float :: stackTail
            | [StackType.ManagedPointer; StackType.ManagedPointer] ->
                StackType.NativeInt :: stackTail
            | [_; StackType.ManagedPointer] | [StackType.ManagedPointer; _] ->
                StackType.ManagedPointer :: stackTail
            | [_; StackType.NativeInt] | [StackType.NativeInt; _] ->
                StackType.NativeInt :: stackTail
            | _ ->
                badStack ()

        | Neg | Not ->
            poppedTypes

        // Binary Comparison or Branch Operations
        // Used for beq, beq.s, bge, bge.s, bge.un, bge.un.s, bgt, bgt.s,
        // bgt.un, bgt.un.s, ble, ble.s, ble.un, ble.un.s, blt, blt.s, blt.un,
        // blt.un.s, bne.un, bne.un.s, ceq, cgt, cgt.un, clt, clt.un
        | Beq _ | Bge _ | Bgt _ | Ble _ | Blt _
        | BneUn _ | BgeUn _ | BgtUn _ | BleUn _ | BltUn _ ->
            stackTail
        | Ceq | Cgt | CgtUn | Clt | CltUn ->
            StackType.Int32 :: stackTail

        // The shl and shr instructions return the same type as their first operand
        // and their second operand shall be of type int32 or native int
        | Shl | Shr | ShrUn ->
            match poppedTypes with
            | [StackType.Int32; fstOpType] | [StackType.NativeInt; fstOpType] ->
                fstOpType :: stackTail
            | _ ->
                badStack ()

        // Integer Operations: Used for and, div.un, not, or, rem.un, xor
        // Note: I put Not with Neg above
        | And | DivUn | Or | RemUn | Xor ->
            match poppedTypes with
            | [StackType.Int32; StackType.Int32] ->
                StackType.Int32 :: stackTail
            | [StackType.Int64; StackType.Int64] ->
                StackType.Int64 :: stackTail
            | [StackType.NativeInt; _] | [_; StackType.NativeInt] ->
                StackType.NativeInt :: stackTail
            | _ ->
                badStack ()

        // Overflow Arithmetic Operations: Used for add.ovf, add.ovf.un,
        // mul.ovf, mul.ovf.un, sub.ovf, and sub.ovf.un
        | AddOvf | AddOvfUn | MulOvf | MulOvfUn | SubOvf | SubOvfUn ->
            match poppedTypes with
            | [StackType.Int32; StackType.Int32] ->
                StackType.Int32 :: stackTail
            | [StackType.Int64; StackType.Int64] ->
                StackType.Int64 :: stackTail
            | [StackType.ManagedPointer; StackType.ManagedPointer] ->
                StackType.NativeInt :: stackTail
            | [_; StackType.ManagedPointer] | [StackType.ManagedPointer; _] ->
                StackType.ManagedPointer :: stackTail
            | [StackType.NativeInt; _] | [_; StackType.NativeInt] ->
                StackType.NativeInt :: stackTail
            | _ ->
                badStack ()

        // data conversion
        | ConvI1 | ConvI2 | ConvI4 | ConvU4 | ConvU2 | ConvU1
        | ConvOvfI1 | ConvOvfU1 | ConvOvfI2 | ConvOvfU2 | ConvOvfI4 | ConvOvfU4
        | ConvOvfI1Un | ConvOvfI2Un | ConvOvfI4Un | ConvOvfU1Un | ConvOvfU2Un | ConvOvfU4Un ->
            StackType.Int32 :: stackTail
        | ConvI8 | ConvU8 | ConvOvfI8Un | ConvOvfU8Un | ConvOvfI8 | ConvOvfU8 ->
            StackType.Int64 :: stackTail
        | ConvR4 | ConvR8 | ConvRUn ->
            StackType.Float :: stackTail
        | ConvI | ConvU | ConvOvfIUn | ConvOvfUUn | ConvOvfI | ConvOvfU ->
            StackType.NativeInt :: stackTail

        | Brfalse _ | Brtrue _ ->
            match poppedTypes with
            | [_] -> stackTail
            | _ -> badStack ()

        | Br _ ->
            match poppedTypes with
            | [] -> stackTail
            | _ -> badStack ()

        | LdindI1 _ | LdindU1 _ | LdindI2 _ | LdindU2 _ | LdindI4 _ | LdindU4 _ ->
            match poppedTypes with
            | [NativeInt] | [ManagedPointer] -> StackType.Int32 :: stackTail
            | _ -> badStack ()
        | LdindI8 _ ->
            match poppedTypes with
            | [NativeInt] | [ManagedPointer] -> StackType.Int64 :: stackTail
            | _ -> badStack ()
        | LdindI _ ->
            match poppedTypes with
            | [NativeInt] | [ManagedPointer] -> StackType.NativeInt :: stackTail
            | _ -> badStack ()
        | LdindR4 _ | LdindR8 _ ->
            match poppedTypes with
            | [NativeInt] | [ManagedPointer] -> StackType.Float :: stackTail
            | _ -> badStack ()
        | LdindRef _ ->
            match poppedTypes with
            | [NativeInt] | [ManagedPointer] -> StackType.ObjectRef :: stackTail
            | _ -> badStack ()

        | Break | Nop ->
            match poppedTypes with
            | [] -> stackTail
            | _ -> badStack ()

        | LdcI4 _ ->
            match poppedTypes with
            | [] -> StackType.Int32 :: stackTail
            | _ -> badStack ()
        | LdcI8 _ ->
            match poppedTypes with
            | [] -> StackType.Int64 :: stackTail
            | _ -> badStack ()
        | LdcR4 _ | LdcR8 _ ->
            match poppedTypes with
            | [] -> StackType.Float :: stackTail
            | _ -> badStack ()

        | LdelemI1 | LdelemU1 | LdelemI2 | LdelemU2 | LdelemI4 | LdelemU4 ->
            StackType.Int32 :: stackTail
        | LdelemI8 ->
            StackType.Int64 :: stackTail
        | LdelemI ->
            StackType.NativeInt :: stackTail
        | LdelemR4 | LdelemR8 ->
            StackType.Float :: stackTail
        | LdelemRef ->
            StackType.ObjectRef :: stackTail

        | StelemI | StelemI1 | StelemI2 | StelemI4
        | StelemI8 | StelemR4 | StelemR8 | StelemRef | Stelem _ ->
            match poppedTypes with
            | [_; StackType.Int32; StackType.ObjectRef]
            | [_; StackType.NativeInt; StackType.ObjectRef] ->
                stackTail
            | _ ->
                badStack ()

        | StindRef _ | StindI1 _ | StindI2 _ | StindI4 _
        | StindI8 _ | StindR4 _ | StindR8 _ | StindI _ ->
            stackTail

        | Dup ->
            match poppedTypes with
            | [item] -> item :: item :: stackTail
            | _ -> badStack ()

        | Ldnull | Ldstr _ ->
            match poppedTypes with
            | [] -> StackType.ObjectRef :: stackTail
            | _ -> badStack ()
        
        | Starg _ | Stloc _ | Stsfld _ ->
            match poppedTypes with
            | [_] -> stackTail
            | _ -> badStack ()
        
        | Stfld _ ->
            match poppedTypes with
            | [_; (ObjectRef | NativeInt | ManagedPointer)] -> stackTail
            | _ -> badStack ()
        
        | Stobj _ ->
            match poppedTypes with
            | [_; _] -> stackTail
            | _ -> badStack ()

        | Ldlen ->
            match poppedTypes with
            | [StackType.ObjectRef] -> StackType.NativeInt :: stackTail
            | _ -> badStack ()

        | Pop ->
            match poppedTypes with
            | [_] -> stackTail
            | _ -> badStack ()

        | Newarr _ ->
            match poppedTypes with
            | [StackType.Int32] | [StackType.NativeInt] -> StackType.ObjectRef :: stackTail
            | _ -> badStack ()

        | Box _ ->
            match poppedTypes with
            | [_] -> StackType.ObjectRef :: stackTail
            | _ -> badStack ()

        | Throw ->
            match poppedTypes with
            | [StackType.ObjectRef] -> []
            | _ -> badStack ()
        
        | Jmp _ ->
            match poppedTypes with
            | [] -> []
            | _ -> badStack ()

        | Ret ->
            match poppedTypes with
            | [] | [_] -> []
            | _ -> badStack ()

        | Leave _ -> []

        | Ckfinite -> stackTypes

        | Endfinally -> []
        
        | Ldftn _ -> StackType.NativeInt :: stackTail

        | Call (_, methdRef) | Callvirt (_, _, methdRef) ->
            match methdRef.ReturnType.MetadataType with
            | MetadataType.Void -> stackTail
            | _ -> asIntermediateType methdRef.ReturnType :: stackTail

        | Calli (_, callSite) ->
            match callSite.ReturnType.MetadataType with
            | MetadataType.Void -> stackTail
            | _ -> asIntermediateType callSite.ReturnType :: stackTail

        | Newobj methodRef ->
            asIntermediateType methodRef.DeclaringType :: stackTail

        | Cpobj _ ->
            match poppedTypes with
            | [(NativeInt | ManagedPointer); (NativeInt | ManagedPointer)] ->
                []
            | _ ->
                badStack ()

        | Ldarga _ | Ldloca _ ->
            StackType.ManagedPointer :: stackTail
        
        | Ldflda _ ->
            match poppedTypes with
            | [(ObjectRef | ManagedPointer)] ->
                ManagedPointer :: stackTail
            | [NativeInt] ->
                NativeInt :: stackTail
            | _ ->
                badStack ()

        | Ldelema _ ->
            match poppedTypes with
            | [(StackType.Int32 | StackType.NativeInt); StackType.ObjectRef] ->
                StackType.ManagedPointer :: stackTail
            | _ ->
                badStack ()

        | Ldelem typeRef ->
            match poppedTypes with
            | [(StackType.Int32 | StackType.NativeInt); StackType.ObjectRef] ->
                asIntermediateType typeRef :: stackTail
            | _ ->
                badStack ()

        | Ldarg paramDef ->
            match poppedTypes with
            | [] -> asIntermediateType paramDef.ParameterType :: stackTail
            | _ -> badStack ()

        | Ldloc varDef ->
            match poppedTypes with
            | [] -> asIntermediateType varDef.VariableType :: stackTail
            | _ -> badStack ()

        
        | Ldobj (_, _, typeRef) ->
            match poppedTypes with
            | [NativeInt | ManagedPointer] -> asIntermediateType typeRef :: stackTail
            | _ -> badStack ()

        | Switch _ ->
            stackTail

        | Isinst _ | Castclass _ ->
            match poppedTypes with
            | [ObjectRef] -> ObjectRef :: stackTail
            | _ -> badStack ()

        | Ldfld (_, _, fieldRef) | Ldsfld (_, fieldRef) ->
            match poppedTypes with
            | [ObjectRef | ManagedPointer | NativeInt] ->
                asIntermediateType fieldRef.FieldType :: stackTail
            | _ ->
                badStack ()

        | Unbox typeRef ->
            match poppedTypes with
            | [ObjectRef] -> asIntermediateType typeRef :: stackTail
            | _ -> badStack ()

        | UnboxAny typeRef ->
            match poppedTypes with
            | [ObjectRef] -> asIntermediateType typeRef :: stackTail
            | _ -> badStack ()

        | Mkrefany _ ->
            match poppedTypes with
            | [ManagedPointer | NativeInt] -> ObjectRef :: stackTail
            | _ -> badStack ()

        | Refanyval typeRef ->
            // Correct CIL ensures that typedRef is a valid typed reference (created by a previous call to mkrefany).
            match poppedTypes with
            | [ObjectRef] -> asIntermediateType typeRef :: stackTail
            | _ -> badStack ()

        | Refanytype ->
            match poppedTypes with
            | [ObjectRef] -> ObjectRef :: stackTail
            | _ -> badStack ()

        | Ldtoken _ ->
            match poppedTypes with
            | [] -> ObjectRef :: stackTail
            | _ -> badStack ()

        | Arglist ->
            match poppedTypes with
            | [] -> ObjectRef :: stackTail
            | _ -> badStack ()

        | Ldvirtftn _ ->
            match poppedTypes with
            | [ObjectRef] -> NativeInt :: stackTail
            | _ -> badStack ()
            
        | Localloc ->
            match poppedTypes, stackTail with
            | [NativeInt | StackType.Int32], [] -> [NativeInt]
            | _ -> badStack ()

        | Endfilter ->
            match poppedTypes with
            | [StackType.Int32] -> stackTail
            | _ -> badStack ()

        | Initobj _ ->
            match poppedTypes with
            | [ManagedPointer | NativeInt] -> stackTail
            | _ -> badStack ()

        | Cpblk | Initblk _ ->
            match poppedTypes with
            | [StackType.Int32; (ManagedPointer | NativeInt); (ManagedPointer | NativeInt)] ->
                stackTail
            | _ ->
                badStack ()

        | Rethrow ->
            match poppedTypes with
            | [] -> stackTail
            | _ -> badStack ()

        | Sizeof _ ->
            match poppedTypes with
            | [] -> StackType.Int32 :: stackTail
            | _ -> badStack ()

        | Ldsflda (_, fieldRef) ->
            match poppedTypes with
            | [] ->
                let fieldDef = fieldRef.Resolve ()
                let pushType = if fieldDef.RVA = 0 then ManagedPointer else NativeInt
                pushType :: stackTail
            | _ ->
                badStack ()

/// extend cecil's MethodBody class
type MethodBody with

    /// get's all parameters including any implicit this parameters
    member x.AllParameters = [|
        let meth = x.Method
        if meth.HasThis then
            //yield x.ThisParameter

            // ThisParameter returns a bad type for valuetypes
            // see "Partition II 13.3 Methods of value types"
            let thisParamTy =
                match meth.DeclaringType.MetadataType with
                | MetadataType.Boolean | MetadataType.Char | MetadataType.SByte | MetadataType.Byte
                | MetadataType.Int16 | MetadataType.UInt16 | MetadataType.Int32 | MetadataType.UInt32
                | MetadataType.Int64 | MetadataType.UInt64 | MetadataType.Single | MetadataType.Double
                | MetadataType.Pointer | MetadataType.ValueType
                | MetadataType.IntPtr | MetadataType.UIntPtr | MetadataType.FunctionPointer ->
                    new PointerType(meth.DeclaringType) :> TypeReference
                | _ ->
                    meth.DeclaringType :> TypeReference
            yield new ParameterDefinition ("0", ParameterAttributes.None, thisParamTy)
        for p in meth.Parameters do
            yield p|]

    /// This function gives a "view" of the Instructions property which is
    /// simplified (fewer instruction types with explicit code blocks) and more
    /// type-safe
    ///
    /// TODO: do something with x.ExceptionHandlers
    member x.BasicBlocks =
        // SimplifyMacros will expand all "macro" instructions for us.
        // See: MethodBodyRocks.SimplifyMacros
        x.SimplifyMacros ()
        let insts = Array.ofSeq x.Instructions
        
        // collection of all branch destinations (from switch and br instructions)
        // these will be used to figure out where our code blocks start
        // and stop
        //
        // TODO this is incomplete. need to consider exceptions
        let blockStartOffsets = seq {
            yield 0
            for i in 0 .. insts.Length - 1 do
                let inst = insts.[i]

                // if this is a branch, switch or return the next instruction is
                // a block start
                if i + 1 < insts.Length then
                    match inst.OpCode.FlowControl with
                    | FlowControl.Branch | FlowControl.Cond_Branch
                    | FlowControl.Return (* | FlowControl.Throw *) ->
                        yield insts.[i + 1].Offset
                    | _ ->
                        ()

                // add any branch or switch targets
                match inst.OpCode.OperandType with
                | OperandType.ShortInlineBrTarget | OperandType.InlineBrTarget ->
                    let destInst = inst.Operand :?> Instruction
                    yield destInst.Offset
                | OperandType.InlineSwitch ->
                    for destInst in inst.Operand :?> Instruction array do
                        yield destInst.Offset
                | _ ->
                    ()}
    
        // code blocks will be determined by the destination instructions
        // of all branch instructions. Also always include the 1st instruction
        let basicBlocks =
            Set.ofSeq blockStartOffsets
            |> Array.ofSeq
            |> Array.sort
            |> Array.map (fun offset -> new BasicBlock(offset))
        
        // all of the remaining code in this function is for filling in the
        // "Instructions" property for the BasicBlocks we just created
        
        let instOffsets = [|for inst in insts -> inst.Offset|]
        let indexOfInstAt offset =
            let i = System.Array.BinarySearch (instOffsets, offset)
            if i >= 0 then
                i
            else
                failwithf "bad instruction offset: %i" offset
        let blockInstStartIndexes =
            [|for bl in basicBlocks -> indexOfInstAt bl.OffsetBytes|]
        let blockInstCounts = [|
            for ii in 0 .. blockInstStartIndexes.Length - 1 do
                let currStart = blockInstStartIndexes.[ii]
                let currEnd =
                    if ii = blockInstStartIndexes.Length - 1 then
                        insts.Length
                    else
                        blockInstStartIndexes.[ii + 1]
                yield currEnd - currStart|]
        
        // this function will get the block starting with the given instruction
        let blockForInst (inst : Instruction) =
            let i = indexOfInstAt inst.Offset
            let bIndex = System.Array.BinarySearch (blockInstStartIndexes, i)
            if bIndex >= 0 then
                basicBlocks.[bIndex]
            else
                failwithf "there is no block starting at instruction index %i" i
        
        // creates a single code block of instructions
        let readBlockInsts (blockIndex : int) =
            let fstInstIndex = blockInstStartIndexes.[blockIndex]
            let lstInstIndex = fstInstIndex + blockInstCounts.[blockIndex] - 1
            
            // a little sanity check first
            if blockIndex >= 1 then
                match insts.[fstInstIndex - 1].OpCode.OpCodeType with
                | OpCodeType.Prefix ->
                    failwithf "code blocks should not be preceded by prefix op codes"
                | _ -> ()
            
            let currInstIndex = ref fstInstIndex
            
            // reads a single abstract instruction (this can span more than
            // a single "real" instruction since it may include instruction
            // prefixes)
            let rec nextInst
                    (constrainedPrefix : TypeReference option)
                    (noPrefix : byte)
                    (readonlyPrefix : bool)
                    (tailPrefix : bool)
                    (unalignedPrefix : byte option)
                    (volatilePrefix : bool) =
    
                let inst = insts.[!currInstIndex]
                currInstIndex := !currInstIndex + 1
                
                let brDestBasicBlock () =
                    blockForInst (inst.Operand :?> Instruction)
                
                match inst.OpCode.Code with
                | Code.Nop -> Nop
                | Code.Break -> Break
                | Code.Ldnull -> Ldnull
                | Code.Ldc_I4 -> LdcI4 (inst.Operand :?> int)
                | Code.Ldc_I8 -> LdcI8 (inst.Operand :?> int64)
                | Code.Ldc_R4 -> LdcR4 (inst.Operand :?> single)
                | Code.Ldc_R8 -> LdcR8 (inst.Operand :?> double)
                | Code.Dup -> Dup
                | Code.Pop -> Pop
                | Code.Jmp -> Jmp (inst.Operand :?> MethodReference)
                | Code.Call -> Call (tailPrefix, inst.Operand :?> MethodReference)
                | Code.Calli -> Calli (tailPrefix, inst.Operand :?> CallSite)
                | Code.Ret -> Ret
                | Code.Br -> Br <| brDestBasicBlock ()
                | Code.Brfalse -> Brfalse (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Brtrue -> Brtrue (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Beq -> Beq (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Bge -> Bge (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Bgt -> Bgt (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Ble -> Ble (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Blt -> Blt (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Bne_Un -> BneUn (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Bge_Un -> BgeUn (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Bgt_Un -> BgtUn (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Ble_Un -> BleUn (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Blt_Un -> BltUn (brDestBasicBlock (), basicBlocks.[blockIndex + 1])
                | Code.Switch ->
                    let destBlocks =
                        [|for destInst in inst.Operand :?> Instruction array do
                            yield blockForInst destInst|]
                    Switch (destBlocks, basicBlocks.[blockIndex + 1])
                | Code.Ldind_I1 -> LdindI1 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_U1 -> LdindU1 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_I2 -> LdindI2 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_U2 -> LdindU2 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_I4 -> LdindI4 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_U4 -> LdindU4 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_I8 -> LdindI8 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_I -> LdindI (unalignedPrefix, volatilePrefix)
                | Code.Ldind_R4 -> LdindR4 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_R8 -> LdindR8 (unalignedPrefix, volatilePrefix)
                | Code.Ldind_Ref -> LdindRef (unalignedPrefix, volatilePrefix)
                | Code.Stind_Ref -> StindRef (unalignedPrefix, volatilePrefix)
                | Code.Stind_I1 -> StindI1 (unalignedPrefix, volatilePrefix)
                | Code.Stind_I2 -> StindI2 (unalignedPrefix, volatilePrefix)
                | Code.Stind_I4 -> StindI4 (unalignedPrefix, volatilePrefix)
                | Code.Stind_I8 -> StindI8 (unalignedPrefix, volatilePrefix)
                | Code.Stind_R4 -> StindR4 (unalignedPrefix, volatilePrefix)
                | Code.Stind_R8 -> StindR8 (unalignedPrefix, volatilePrefix)
                | Code.Add -> Add
                | Code.Sub -> Sub
                | Code.Mul -> Mul
                | Code.Div -> Div
                | Code.Div_Un -> DivUn
                | Code.Rem -> Rem
                | Code.Rem_Un -> RemUn
                | Code.And -> And
                | Code.Or -> Or
                | Code.Xor -> Xor
                | Code.Shl -> Shl
                | Code.Shr -> Shr
                | Code.Shr_Un -> ShrUn
                | Code.Neg -> Neg
                | Code.Not -> Not
                | Code.Conv_I1 -> ConvI1
                | Code.Conv_I2 -> ConvI2
                | Code.Conv_I4 -> ConvI4
                | Code.Conv_I8 -> ConvI8
                | Code.Conv_R4 -> ConvR4
                | Code.Conv_R8 -> ConvR8
                | Code.Conv_U4 -> ConvU4
                | Code.Conv_U8 -> ConvU8
                | Code.Callvirt -> Callvirt (tailPrefix, constrainedPrefix, inst.Operand :?> MethodReference)
                | Code.Cpobj -> Cpobj (inst.Operand :?> TypeReference)
                | Code.Ldobj -> Ldobj (unalignedPrefix, volatilePrefix, inst.Operand :?> TypeReference)
                | Code.Ldstr -> Ldstr (inst.Operand :?> string)
                | Code.Newobj -> Newobj (inst.Operand :?> MethodReference)
                | Code.Castclass -> Castclass (inst.Operand :?> TypeReference)
                | Code.Isinst -> Isinst (inst.Operand :?> TypeReference)
                | Code.Conv_R_Un -> ConvRUn
                | Code.Unbox -> Unbox (inst.Operand :?> TypeReference)
                | Code.Throw -> Throw
                | Code.Ldfld -> Ldfld (unalignedPrefix, volatilePrefix, inst.Operand :?> FieldReference)
                | Code.Ldflda -> Ldflda (unalignedPrefix, volatilePrefix, inst.Operand :?> FieldReference)
                | Code.Stfld -> Stfld (unalignedPrefix, volatilePrefix, inst.Operand :?> FieldReference)
                | Code.Ldsfld -> Ldsfld (volatilePrefix, inst.Operand :?> FieldReference)
                | Code.Ldsflda -> Ldsflda (volatilePrefix, inst.Operand :?> FieldReference)
                | Code.Stsfld -> Stsfld (volatilePrefix, inst.Operand :?> FieldReference)
                | Code.Stobj -> Stobj (unalignedPrefix, volatilePrefix, inst.Operand :?> TypeReference)
                | Code.Conv_Ovf_I1_Un -> ConvOvfI1Un
                | Code.Conv_Ovf_I2_Un -> ConvOvfI2Un
                | Code.Conv_Ovf_I4_Un -> ConvOvfI4Un
                | Code.Conv_Ovf_I8_Un -> ConvOvfI8Un
                | Code.Conv_Ovf_U1_Un -> ConvOvfU1Un
                | Code.Conv_Ovf_U2_Un -> ConvOvfU2Un
                | Code.Conv_Ovf_U4_Un -> ConvOvfU4Un
                | Code.Conv_Ovf_U8_Un -> ConvOvfU8Un
                | Code.Conv_Ovf_I_Un -> ConvOvfIUn
                | Code.Conv_Ovf_U_Un -> ConvOvfUUn
                | Code.Box -> Box (inst.Operand :?> TypeReference)
                | Code.Newarr -> Newarr (inst.Operand :?> TypeReference)
                | Code.Ldlen -> Ldlen
                | Code.Ldelema -> Ldelema (readonlyPrefix, inst.Operand :?> TypeReference)
                | Code.Ldelem_I1 -> LdelemI1
                | Code.Ldelem_U1 -> LdelemU1
                | Code.Ldelem_I2 -> LdelemI2
                | Code.Ldelem_U2 -> LdelemU2
                | Code.Ldelem_I4 -> LdelemI4
                | Code.Ldelem_U4 -> LdelemU4
                | Code.Ldelem_I8 -> LdelemI8
                | Code.Ldelem_I -> LdelemI
                | Code.Ldelem_R4 -> LdelemR4
                | Code.Ldelem_R8 -> LdelemR8
                | Code.Ldelem_Ref -> LdelemRef
                | Code.Stelem_I -> StelemI
                | Code.Stelem_I1 -> StelemI1
                | Code.Stelem_I2 -> StelemI2
                | Code.Stelem_I4 -> StelemI4
                | Code.Stelem_I8 -> StelemI8
                | Code.Stelem_R4 -> StelemR4
                | Code.Stelem_R8 -> StelemR8
                | Code.Stelem_Ref -> StelemRef
                | Code.Ldelem_Any -> Ldelem (inst.Operand :?> TypeReference)
                | Code.Stelem_Any -> Stelem (inst.Operand :?> TypeReference)
                | Code.Unbox_Any -> UnboxAny (inst.Operand :?> TypeReference)
                | Code.Conv_Ovf_I1 -> ConvOvfI1
                | Code.Conv_Ovf_U1 -> ConvOvfU1
                | Code.Conv_Ovf_I2 -> ConvOvfI2
                | Code.Conv_Ovf_U2 -> ConvOvfU2
                | Code.Conv_Ovf_I4 -> ConvOvfI4
                | Code.Conv_Ovf_U4 -> ConvOvfU4
                | Code.Conv_Ovf_I8 -> ConvOvfI8
                | Code.Conv_Ovf_U8 -> ConvOvfU8
                | Code.Refanyval -> Refanyval (inst.Operand :?> TypeReference)
                | Code.Ckfinite -> Ckfinite
                | Code.Mkrefany -> Mkrefany (inst.Operand :?> TypeReference)
                | Code.Ldtoken -> Ldtoken (inst.Operand :?> IMetadataTokenProvider)
                | Code.Conv_U2 -> ConvU2
                | Code.Conv_U1 -> ConvU1
                | Code.Conv_I -> ConvI
                | Code.Conv_Ovf_I -> ConvOvfI
                | Code.Conv_Ovf_U -> ConvOvfU
                | Code.Add_Ovf -> AddOvf
                | Code.Add_Ovf_Un -> AddOvfUn
                | Code.Mul_Ovf -> MulOvf
                | Code.Mul_Ovf_Un -> MulOvfUn
                | Code.Sub_Ovf -> SubOvf
                | Code.Sub_Ovf_Un -> SubOvfUn
                | Code.Endfinally -> Endfinally
                | Code.Leave -> Leave <| brDestBasicBlock ()
                | Code.Stind_I -> StindI (unalignedPrefix, volatilePrefix)
                | Code.Conv_U -> ConvU
                | Code.Arglist -> Arglist
                | Code.Ceq -> Ceq
                | Code.Cgt -> Cgt
                | Code.Cgt_Un -> CgtUn
                | Code.Clt -> Clt
                | Code.Clt_Un -> CltUn
                | Code.Ldftn -> Ldftn (inst.Operand :?> MethodReference)
                | Code.Ldvirtftn -> Ldvirtftn (inst.Operand :?> MethodReference)
                | Code.Ldarg -> Ldarg (inst.Operand :?> ParameterDefinition)
                | Code.Ldarga -> Ldarga (inst.Operand :?> ParameterDefinition)
                | Code.Starg -> Starg (inst.Operand :?> ParameterDefinition)
                | Code.Ldloc -> Ldloc (inst.Operand :?> VariableDefinition)
                | Code.Ldloca -> Ldloca (inst.Operand :?> VariableDefinition)
                | Code.Stloc -> Stloc (inst.Operand :?> VariableDefinition)
                | Code.Localloc -> Localloc
                | Code.Endfilter -> Endfilter
                | Code.Unaligned ->
                    match unalignedPrefix with
                    | Some _ ->
                        failwith "repeated unaligned. prefixes"
                    | None ->
                        let op = inst.Operand :?> byte
                        nextInst
                            constrainedPrefix
                            noPrefix
                            readonlyPrefix
                            tailPrefix
                            (Some op)
                            volatilePrefix
                | Code.Volatile ->
                    if volatilePrefix then
                        failwith "repeated volatile. prefixes"
                    else
                        nextInst
                            constrainedPrefix
                            noPrefix
                            readonlyPrefix
                            tailPrefix
                            unalignedPrefix
                            true
                | Code.Tail ->
                    if tailPrefix then
                        failwith "repeated tail. prefixes"
                    else
                        nextInst
                            constrainedPrefix
                            noPrefix
                            readonlyPrefix
                            true
                            unalignedPrefix
                            volatilePrefix
                | Code.Initobj -> Initobj (inst.Operand :?> TypeReference)
                | Code.Constrained ->
                    match constrainedPrefix with
                    | Some _ ->
                        failwith "repeated constrained. prefixes"
                    | None ->
                        let op = inst.Operand :?> TypeReference
                        nextInst
                            (Some op)
                            noPrefix
                            readonlyPrefix
                            tailPrefix
                            unalignedPrefix
                            volatilePrefix
                | Code.Cpblk -> Cpblk
                | Code.Initblk -> Initblk (unalignedPrefix, volatilePrefix)
                | Code.No ->
                    // TODO is it worth doing anything with this?
                    let op = inst.Operand :?> byte
                    nextInst
                        constrainedPrefix
                        (op ||| noPrefix)
                        readonlyPrefix
                        tailPrefix
                        unalignedPrefix
                        volatilePrefix
                | Code.Rethrow -> Rethrow
                | Code.Sizeof -> Sizeof (inst.Operand :?> TypeReference)
                | Code.Refanytype -> Refanytype
                | Code.Readonly ->
                    if readonlyPrefix then
                        failwith "repeated readonly. prefixes"
                    else
                        nextInst
                            constrainedPrefix
                            noPrefix
                            true
                            tailPrefix
                            unalignedPrefix
                            volatilePrefix
                | Code.Ldarg_0 | Code.Ldarg_1 | Code.Ldarg_2 | Code.Ldarg_3
                | Code.Ldloc_0 | Code.Ldloc_1 | Code.Ldloc_2 | Code.Ldloc_3
                | Code.Stloc_0 | Code.Stloc_1 | Code.Stloc_2 | Code.Stloc_3
                | Code.Ldarg_S | Code.Ldarga_S | Code.Starg_S | Code.Ldloc_S
                | Code.Ldloca_S | Code.Stloc_S
                | Code.Ldc_I4_M1 | Code.Ldc_I4_0 | Code.Ldc_I4_1 | Code.Ldc_I4_2
                | Code.Ldc_I4_3 | Code.Ldc_I4_4 | Code.Ldc_I4_5 | Code.Ldc_I4_6
                | Code.Ldc_I4_7 | Code.Ldc_I4_8 | Code.Ldc_I4_S
                | Code.Br_S | Code.Brfalse_S | Code.Brtrue_S
                | Code.Beq_S | Code.Bge_S | Code.Bgt_S | Code.Ble_S | Code.Blt_S
                | Code.Bne_Un_S | Code.Bge_Un_S | Code.Bgt_Un_S
                | Code.Ble_Un_S | Code.Blt_Un_S
                | Code.Leave_S ->
                    failwithf "this instruction should have been removed by cecil MethodBodyRocks.SimplifyMacros: %A" inst.OpCode.Code
                | _ ->
                    failwithf "unexpected instruction: %A" inst.OpCode.Code
            
            // to read the block we just iterate through instructions
            // using the nextInst function defined above
            [while !currInstIndex <= lstInstIndex do
                let saferInst = nextInst None 0uy false false None false
                let lastCecilInst = insts.[!currInstIndex - 1]
                let popB = lastCecilInst.OpCode.StackBehaviourPop
                let pushB = lastCecilInst.OpCode.StackBehaviourPush
                let flowControl = lastCecilInst.OpCode.FlowControl
                yield new AnnotatedInstruction(saferInst, popB, pushB, flowControl)]
        
        // fill in the instructions property for all code blocks and return
        for blockIndex in 0 .. basicBlocks.Length - 1 do
            let insts = readBlockInsts blockIndex

            // if the last instruction is non-terminal we have to stick on a
            // fall-through branch instruction
            let lastInst = insts.[insts.Length - 1]
            let insts =
                match lastInst.FlowControl with
                | FlowControl.Branch | FlowControl.Cond_Branch | FlowControl.Return | FlowControl.Throw ->
                    insts
                | _ ->
                    let fallthroughBranch =
                        AnnotatedInstruction (
                            Br basicBlocks.[blockIndex + 1],
                            StackBehaviour.Pop0,
                            StackBehaviour.Push0,
                            FlowControl.Branch)
                    insts @ [fallthroughBranch]

            basicBlocks.[blockIndex].Instructions <- insts

        // fill in the initial stack types for all basic blocks
        let alreadyInferredIDs = ref (Set.empty : int Set)
        let rec inferSuccStackTypes (initTypes : StackType list) (bb : BasicBlock) =
            if (!alreadyInferredIDs).Contains bb.OffsetBytes then
                // since we've already inferred stack types for this basic block we
                // just want to assert that the types are the same this time around
                if initTypes <> bb.InitStackTypes then
                    failwithf
                        "missmatch in initial basic block stack types: %A vs %A"
                        initTypes
                        bb.InitStackTypes
            else
                bb.InitStackTypes <- initTypes
                alreadyInferredIDs := (!alreadyInferredIDs).Add bb.OffsetBytes

                let mutable nextInitTypes = initTypes
                for inst in bb.Instructions do
                    nextInitTypes <- inst.UpdateTypes nextInitTypes
                List.iter (inferSuccStackTypes nextInitTypes) bb.Successors
        inferSuccStackTypes [] basicBlocks.[0]

        basicBlocks

type MethodDefinition with
    member x.AllParameters =
        if x.HasBody
        then x.Body.AllParameters
        else Array.ofSeq x.Parameters