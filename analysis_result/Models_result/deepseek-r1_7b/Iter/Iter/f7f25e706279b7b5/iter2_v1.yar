rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with more specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 41 E1 72 ?? ?? ?? FF D2 ?? C3 } // Specific exit decision check
        $pattern1 = { 00 41 E1 96 ?? 8B ?? ?? ?? EA DD EB 14 } // Conditional test pattern
        $pattern2 = { 00 41 E1 A3 ?? 8B 55 14 ED DD } // Specific stack manipulation check

    condition:
        any of them
}