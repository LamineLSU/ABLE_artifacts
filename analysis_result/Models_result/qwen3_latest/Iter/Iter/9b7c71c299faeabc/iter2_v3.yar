rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 08 50 44 00 8B F0 50 83 F8 11 74 05 }  // VirtualAlloc + cmp+je
        $pattern1 = { FF 15 28 50 44 00 85 C0 75 07 }               // VirtualFree + test+jne
        $pattern2 = { 75 07 50 FF 15 50 50 44 00 }                  // jne + ExitProcess call

    condition:
        any of them
}