
open System.Runtime.InteropServices

// TODO think I need to declare dlopen similar to the way malloc is declared
[<DllImport("libc.dll", EntryPoint="putchar")>]
extern void printChar(int c)

let print (cs : char array) =
    for c in cs do
        printChar (int c)

let println (cs : char array) =
    print cs
    printChar (int '\n')

let _ =
    printChar (int 'c')
    printChar (int '\n')

    // I think this line of code is going to kill me
    println [|'h'; 'i'; ' '; 't'; 'h'; 'e'; 'r'; 'e'|]

