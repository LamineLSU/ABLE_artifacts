rule Bypass_Sample
{
    meta:
        description = "Evasion bypass for specific test checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C9 E8 ?? ?? ?? ?? 75 10 ?? }
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 74 ?? }
        $pattern2 = { 8B 45 0F 84 ?? ?? ?? ?? 75 10 ?? }

    condition:
        any of them
}