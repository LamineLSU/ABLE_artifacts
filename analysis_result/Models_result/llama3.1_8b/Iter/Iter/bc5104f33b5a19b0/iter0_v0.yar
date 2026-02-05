rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 ?? FF 15 B8 30 FB 00 }
        $pattern1 = { 74 4B ?? FF 15 B4 30 FB 00 }
        $pattern2 = { 81 C4 CC B3 0C 00 5B }

    condition:
        any of them
}