rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 FF D2 5E 5D C3 } // Call to RtlAllocateHeap and register cleanup
        $pattern1 = { E8 74 0A 00 00 8B 55 14 } // Call to 0041EB27h and subsequent memory access
        $pattern2 = { 52 52 8B 16 50 50 51 51 FF D2 } // Memory validation and second call to edx

    condition:
        any of them
}