
open System.Runtime.InteropServices

// TODO think I need to declare dlopen similar to the way malloc is declared
[<DllImport("libc.dll", EntryPoint="putchar")>]
extern void putchar(int c)

let _ =
    putchar (int 'c')
    putchar (int '\n')
