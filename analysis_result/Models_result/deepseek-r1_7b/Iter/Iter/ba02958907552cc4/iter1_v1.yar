rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with more specific patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 EA EA 74 12 }
        $pattern1 = { 74 12 ?? 8B 45 FC }
        $pattern2 = { BA 21 05 00 EB 6A 40 }

    condition:
        (any of them)
}