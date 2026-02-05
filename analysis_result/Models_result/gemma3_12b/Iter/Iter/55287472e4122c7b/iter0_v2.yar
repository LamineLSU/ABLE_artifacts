rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8B 45 E4 8A 40 01 88 45 E2 8B 4D E8 3A 41 01 }
        $pattern2 = { 83 45 E4 02 83 45 E8 02 80 7D E2 00 75 CC }

    condition:
        any of them
}