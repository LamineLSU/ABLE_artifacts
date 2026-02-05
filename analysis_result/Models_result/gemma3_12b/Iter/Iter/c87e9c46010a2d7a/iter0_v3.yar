rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 74 12 }
        $pattern2 = { 6A 40 53 68 40 11 22 00 33 C9 E8 4B 17 00 00 }

    condition:
        any of them
}