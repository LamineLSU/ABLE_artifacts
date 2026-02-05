rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 83 F8 11 74 05 }  // VirtualAlloc + cmp + je
        $pattern1 = { FF 15 54 F0 42 00 56 5F 5E }         // VirtualFree + stack ops
        $pattern2 = { FF 15 60 F0 42 00 85 C0 }            // VirtualAllocExNuma + test eax

    condition:
        any of them
}