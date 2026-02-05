rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 5A }
        $pattern1 = { 74 ?? 1A 8B 45 FC }
        $pattern2 = { E8 ?? ?? ?? ?? C3 }

    condition:
        any of them
}