rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - adjusted skip offset for better precision"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern1+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 8B ?? F8 }
        $pattern1 = { 8D 9F FE F8 CD 03 ?? }
        $pattern2 = { 6A 5B 5A ?? F0 F3 8C }

    condition:
        any of them
}