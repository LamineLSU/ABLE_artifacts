rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 36 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8B 88 18 0A 00 00 56 50 }
        $pattern2 = { 00 51 8D 51 ?? 8B 06 }

    condition:
        any of them
}