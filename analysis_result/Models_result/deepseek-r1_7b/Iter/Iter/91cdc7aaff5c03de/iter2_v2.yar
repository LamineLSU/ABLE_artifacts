rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass targeting specific return paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4D E4 ?? ?? ?? C3 }
        $pattern1 = { E8 ?? 7C ?? ?? ?? ?? 84 ?? ?? ?? }
        $pattern2 = { ?? ?? ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }

    condition:
        any of them
}