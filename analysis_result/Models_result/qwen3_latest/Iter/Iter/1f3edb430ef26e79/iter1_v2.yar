rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 }  // RtlAllocateHeap call setup
        $pattern1 = { 52 8B 06 83 C4 14 52 FF D0 }  // ExitProcess call setup
        $pattern2 = { 56 50 8D B0 A0 0C 00 00 E8 74 0A 00 00 }  // Indirect call to 0041EB47h

    condition:
        any of them
}