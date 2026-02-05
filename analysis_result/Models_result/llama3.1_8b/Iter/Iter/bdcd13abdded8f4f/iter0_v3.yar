rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { EA 08 00 41 7F 14 ?? ?? ?? ?? }
        $pattern1 = { 00 41 7F 14 6A ?? 5A 8B CE E8 ?? ?? ?? 85 C0 }
        $pattern2 = { 55 EB 8B ?? ?? ?? ?? ?? ?? }

    condition:
        any of them
}