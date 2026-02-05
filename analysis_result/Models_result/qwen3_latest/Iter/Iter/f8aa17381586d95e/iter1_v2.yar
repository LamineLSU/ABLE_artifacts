rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 51 FF D2 5F 5D C3 }  // Call RtlAllocateHeap + stack cleanup
        $pattern1 = { 50 E8 ?? ?? ?? ?? }  // Push eax + call to internal function
        $pattern2 = { 8B 4D 08 8B 51 0A } // Heap-related mov instructions

    condition:
        any of them
}