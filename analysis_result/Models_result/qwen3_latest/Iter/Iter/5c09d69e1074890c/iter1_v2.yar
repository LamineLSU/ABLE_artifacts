rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 } // Heap allocation + control flow
        $pattern1 = { EC 8B 45 08 8B 45 08 } // Memory access + conditional checks
        $pattern2 = { 8D B0 98 0C 00 00 } // LEA instruction for address manipulation

    condition:
        any of them
}