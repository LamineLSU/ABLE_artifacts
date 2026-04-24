rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 5F 5D C3 } // Call RtlAllocateHeap + ret
        $pattern1 = { E8 ?? ?? ?? ?? 8B 5D 0E } // Call 0041EAE7h + mov edx
        $pattern2 = { DC 8B B6 FA 91 97 }        // VM detection (fmul with hardcoded offset)

    condition:
        any of them
}