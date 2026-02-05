rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 16 FF D2 5E 5D C3 } // API call sequence (RtlAllocateHeap)
        $pattern1 = { D8 3C A7 4F 90 4F F8 FC } // Obfuscated floating-point operations
        $pattern2 = { 8D B0 98 0C 00 00 E8 74 0A 00 00 } // Suspicious call to 0041EB77h

    condition:
        any of them
}