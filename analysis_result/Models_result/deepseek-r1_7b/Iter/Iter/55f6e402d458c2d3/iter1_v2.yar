rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting test and conditional jump sequences."
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? 45 FC }
        $pattern1 = { 3D 00 10 00 0F 82 }
        $pattern2 = { EB 0E ?? ?? ?? ?? } // Wildcard for variable offset
}

condition:
    (any of ($pattern0, $pattern1, $pattern2))