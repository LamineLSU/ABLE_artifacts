rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 50 51 FF D2 5E } // API call to RtlAllocateHeap
        $pattern1 = { 50 E8 74 0A 00 00 8B 55 14 } // Internal function call
        $pattern2 = { EC 8B 45 08 8B 45 08 } // VM detection check

    condition:
        any of them
}