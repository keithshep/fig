module Fig.InternalCalls

module Ptr = NativeInterop.NativePtr

type [<NoEquality; NoComparison>] FigArray =
    struct
        val length : nativeint
        val rawArr : nativeint
    end

#nowarn "9"

let initFigFloatArray (arrPtr : nativeptr<FigArray>) (fieldMetadata : nativeint) =
    let arr = Ptr.read arrPtr
    let mutable rawFloatArrPtr = Ptr.ofNativeInt<float> arr.rawArr
    //for _ in 0n .. arr.length - 1n do
    for i = 0 to int arr.length - 1 do
        Ptr.write rawFloatArrPtr 0.0
        rawFloatArrPtr <- Ptr.add rawFloatArrPtr 1

//let InitializeArray (arrPtr : nativeptr<FigArray>)

//let InitializeArray (Array array, RuntimeFieldHandle fldHandle)
//let InitializeArray () = ()