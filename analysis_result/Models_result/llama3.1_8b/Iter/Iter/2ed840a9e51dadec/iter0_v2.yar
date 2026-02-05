rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 83 C4 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 75 ?? 6A ?? 5A }
        $pattern2 = { B9 ?? ?? ?? 03 C3 BA ?? ?? ?? }

    condition:
        any of them
}