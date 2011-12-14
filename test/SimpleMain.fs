
open System.Runtime.InteropServices

// TODO think I need to declare dlopen similar to the way malloc is declared
[<DllImport("libc.dll", EntryPoint="putchar")>]
extern void printChar(int c)

let _ =
    printChar (int 'c')
    printChar (int '\n')
    (*
    let cvec = [|'h'; 'i'; ' '; 't'; 'h'; 'e'; 'r'; 'e'|]
    for c in cvec do
        printChar (int c)
    *)

