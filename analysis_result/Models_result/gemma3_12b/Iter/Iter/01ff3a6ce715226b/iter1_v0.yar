rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 8B 45 ?? 55 8B 6D ?? 8B 4D ?? }
        $pattern2 = { 8B 55 14 8B 5D 18 8B 5B 1C 8B 59 1E }

    condition:
        any of them
}