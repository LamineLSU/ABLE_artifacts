rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 } // API call to RtlAllocateHeap
        $pattern1 = { 50 E8 ?? 09 00 00 } // Call to internal function
        $pattern2 = { 29 15 7D 70 07 22 } // Subtraction instruction for memory modification

    condition:
        any of them
}