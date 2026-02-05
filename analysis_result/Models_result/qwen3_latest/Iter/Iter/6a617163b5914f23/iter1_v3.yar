rule EvasionCheck
{
    meta:
        description = "Detects potential evasion checks or obfuscated execution logic"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
        author = "Your Name"
        date = "2025-04-05"

    strings:
        $a = { C7 85 94 FE FF FF 3C 00 00 00 } // mov with 0x3C
        $b = { 89 9D 98 FE FF FF }              // mov ebx to [ebp-0x168h]
        $c = { FF 15 E8 F1 44 00 }              // call to ShellExecuteEx

    condition:
        all of them
}