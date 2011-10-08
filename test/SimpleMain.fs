
open System.Runtime.InteropServices

// TODO think I need to declare dlopen similar to the way malloc is declared
[<DllImport("libc.dll", EntryPoint="putchar")>]
extern void putChar(int c)

let _ =
    putChar (int 'c')
    putChar (int '\n')
