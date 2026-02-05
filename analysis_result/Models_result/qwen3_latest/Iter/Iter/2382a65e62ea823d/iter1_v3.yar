rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 B9 36 DF 35 55 }  // Test instruction (potential evasion check)
        $pattern1 = { E8 74 0A 00 00 56 }  // Call to 0041EAE7h followed by push esi
        $pattern2 = { 8D B0 98 0C 00 00 }  // LEA instruction (data setup)

    condition:
        any of them
}