rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting multiple exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC ?? ?? ?? ?? 51 ?? 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }
        $pattern1 = { 74 03 ?? 75 01 ?? 8B FC 00 00 ?? ?? }
        $pattern2 = { 8D 95 FF FEFFFF ?? ?? ?? ?? 83 C4 ?? ?? }

    condition:
        any of them
}