module SimpleFunctions

let add (x : int) (y : int) = x + y

let rec gcd (x : int) (y : int) =
    if x = y then
        x
    elif x < y then
        gcd x (y - x)
    else
        gcd (x - y) y

let rec fib = function
    | 0 -> 0
    | 1 -> 1
    | n -> fib (n - 1) + fib (n - 2)

// simple example of mutual recursion
let rec isEven = function
    | 0u -> true
    | n  -> isOdd (n - 1u)
and isOdd = function
    | 0u -> false
    | n  -> isEven (n - 1u)

let power (x : float) (y : int) =
    let mutable retVal = 1.0
    for i = 1 to y do
        retVal <- retVal * x
    retVal

[<ReferenceEquality>]
type Point3D = {x : float; y : float; z : float}

let distSq p = p.x * p.x + p.y * p.y + p.z * p.z

let distSqOf789 () = distSq {x = 7.0; y = 8.0; z = 9.0}

let avgOfTwo (x : float) (y : float) = (x + y) / 2.0

let avg (xs : float array) =
    let mutable sum = 0.0
    for x in xs do
        sum <- sum + x
    sum / float xs.Length

let avgOfFour (a : float) (b : float) (c : float) (d : float) =
    avg [|a; b; c; d|]

(*
//let doubleStrLen (s : string) = s.Length * 2

//open System.Numerics

//let doSomething (bi : BigInteger) =
//    if bi.IsPowerOfTwo then 0 else 1

[<NoEquality; NoComparison>]
type GeoPos =
    struct
        val mutable LatDeg : float
        val mutable LonDeg : float
        new(latDeg : float, lonDeg : float) = {LatDeg = latDeg; LonDeg = lonDeg}
    end

let latPlusLon (gp : GeoPos) =
    gp.LatDeg + gp.LonDeg

let bla () =
    latPlusLon (GeoPos (90.0, 180.0))
*)

// For understanding value types:
// newobj instruction: http://msdn.microsoft.com/en-us/library/system.reflection.emit.opcodes.newobj.aspx
// Partition III 1.6 Table 9. Signature matching
// Partition I 12.1.6.2 Operations on value type instances...
// Partition I 8.9.7 Value Types
