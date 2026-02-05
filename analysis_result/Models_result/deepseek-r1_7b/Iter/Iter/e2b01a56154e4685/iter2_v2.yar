rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting three distinct call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 05 00 ?? ?? ?? ?? 0F C4 }
        $pattern1 = { 74 0F 8A ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5B ?? ?? ?? ?? A7 C3 }

    condition:
        any of them
}