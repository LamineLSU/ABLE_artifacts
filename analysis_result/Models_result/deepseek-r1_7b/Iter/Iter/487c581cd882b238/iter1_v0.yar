rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved with multiple strategies targeting decision points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 74 12 5B EB 03 C1 AD EA EC 03 C3 AD EA EB }
        $pattern2 = { E8 25 05 00 00 CA ?? ?? ?? 00 9D 5E 83 }
}

condition:
    (any of the patterns match)