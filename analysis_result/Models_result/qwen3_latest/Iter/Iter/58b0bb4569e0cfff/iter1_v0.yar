rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 44 09 00 00 C3 }  // Call to RtlAllocateHeap followed by RET
        $pattern1 = { 6A 35 6A 35 6A 35 6A 00 6A 00 6A 00 51 }  // Repeated PUSH operations
        $pattern2 = { 8D B0 74 0C 00 00 }  // LEA instruction for address calculation

    condition:
        any of them
}