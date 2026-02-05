rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 7D FC 00 75 08 }  // Conditional check before ExitProcess
        $pattern1 = { FF 15 B4 7D 42 00 }   // Call to GetCurrentProcess
        $pattern2 = { FF 15 5C 7D 42 00 }   // Call to VirtualAllocExNuma

    condition:
        any of them
}