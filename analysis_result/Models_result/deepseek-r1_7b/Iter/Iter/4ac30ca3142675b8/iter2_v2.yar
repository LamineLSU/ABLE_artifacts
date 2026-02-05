rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { 8B ?? 5A 8B CE E8 }
        $pattern1 = { 74 8D ???? 8E ???? }
        $pattern2 = { 6A ?? 5A 8B CE E8 }

    condition:
        any of them
}