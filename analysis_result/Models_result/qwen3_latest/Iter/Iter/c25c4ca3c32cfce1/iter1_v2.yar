rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4C 24 04 FF D2 }  // API call to RtlAllocateHeap
        $pattern1 = { 50 E8 ?? ?? ?? ?? }  // Call to 0041EB17h (loop-related)
        $pattern2 = { 8D B0 98 0C 00 00 }  // LEA instruction for address manipulation

    condition:
        any of them
}