module SimpleFunctions

let add x y = x + y

let rec gcd (x : int) (y : int) =
    if x = y then
        x
    elif x < y then
        gcd x (y - x)
    else
        gcd (x - y) y

