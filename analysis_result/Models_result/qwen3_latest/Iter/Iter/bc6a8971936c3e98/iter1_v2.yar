rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 58 37 61 00 85 C0 75 07 }  // VirtualAllocExNuma call + test/jne
        $pattern1 = { FF 15 BC 36 61 00 }                // ExitProcess call
        $pattern2 = { FF 15 EC 36 61 00 }                // VirtualAlloc call

    condition:
        any of them
}