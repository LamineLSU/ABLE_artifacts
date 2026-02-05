rule Bypass_Sample_Evolved
{
    meta:
        description = "Bypass ExitProcess calls by targeting conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 37 23 00 }  // Example specific pattern from trace
        $pattern1 = { 85 C0 0F 84 FF 38 00 00 }  // Different conditional jump offset
        $pattern2 = { 6A 5B 5A 8B CE E8 57 26 00 00 }  // Unique instruction sequence after JE
    condition:
        (any of the patterns match)
}