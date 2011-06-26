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
type Point = {x : float; y : float; z : float}

let distSq p = p.x * p.x + p.y * p.y + p.z * p.z

let distSqOf789 () = distSq {x = 7.0; y = 8.0; z = 9.0}

