rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 85 C0 8B 45 ?? 8B ?? C3 A1 ?? ?? ?? ?? }
        $pattern2 = { C3 A1 ?? ?? ?? ?? ?? ?? 6A ?? 5A }

    condition:
        any of them
}