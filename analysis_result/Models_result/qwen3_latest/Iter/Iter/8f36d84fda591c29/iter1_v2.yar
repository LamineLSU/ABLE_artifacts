rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { ?? ?? ?? FF D2 5E 5D C3 }  // RtlAllocateHeap call + return sequence
        $pattern1 = { E8 24 13 00 00 8B 55 14 }  // Call to 0041F1C3h followed by edx load
        $pattern2 = { 8B 88 40 08 00 00 }         // Memory access to [eax+0840h]

    condition:
        any of them
}