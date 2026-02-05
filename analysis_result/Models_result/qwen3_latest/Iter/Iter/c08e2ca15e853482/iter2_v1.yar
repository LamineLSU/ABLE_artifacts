rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 83 F8 11 74 05 } // VirtualAlloc + CMP/JE
        $pattern1 = { 85 C9 0B C0 F8 58 85 F6 74 2B }         // Test ESI/JE sequence
        $pattern2 = { FF 15 ?? ?? ?? ?? 85 C0 75 07 }     // VirtualAllocExNuma + TEST/JNE

    condition:
        any of them
}