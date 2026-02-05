rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 4D 47 A9 C5 1E B6 55 } // Test instruction with surrounding bytes
        $pattern1 = { 50 E8 74 0A 00 00 }     // Call to 0041EC07h
        $pattern2 = { 52 8B 16 50 51 FF D2 }   // Sequence leading to RtlAllocateHeap

    condition:
        any of them
}