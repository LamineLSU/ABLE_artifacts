rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 54 00 00 00 B9 0A 00 00 00 33 D2 F7 F1 83 FA 05 75 02 }  // GetTickCount + div + cmp + jne
        $pattern1 = { 6A 00 E8 ?? 01 00 00 }  // Push 0 + ExitProcess call (offset varies)
        $pattern2 = { 83 FA 05 75 02 EB 02 }  // cmp edx,05h + jne + jmp (conditional chain)

    condition:
        any of them
}