rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 83 F8 11 74 05 }  // CMP EAX, 11h + JE (allocation check)
        $pattern1 = { FF 15 ?? 63 45 00 }  // VirtualFree (hidden import)
        $pattern2 = { FF 15 ?? 64 45 00 }  // VirtualAllocExNuma (hidden import)

    condition:
        any of them
}