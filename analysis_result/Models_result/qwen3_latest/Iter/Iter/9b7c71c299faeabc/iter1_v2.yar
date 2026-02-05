rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 83 F8 11 74 05 }  // VirtualAlloc check with cmp/jmp
        $pattern1 = { FF 15 00 50 44 00 85 C0 75 07 }      // VirtualAllocExNuma check with test/jmp
        $pattern2 = { FF 15 50 50 44 00 }                  // Direct ExitProcess call

    condition:
        any of them
}