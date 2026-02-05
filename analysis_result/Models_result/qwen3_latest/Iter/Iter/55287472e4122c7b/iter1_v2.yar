rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 83 F8 11 74 05 }  // cmp eax, 11h + je (VirtualAlloc check)
        $pattern1 = { FF 15 74 64 45 00 }  // call VirtualAlloc
        $pattern2 = { FF 15 9C 63 45 00 }  // call VirtualFree

    condition:
        any of them
}