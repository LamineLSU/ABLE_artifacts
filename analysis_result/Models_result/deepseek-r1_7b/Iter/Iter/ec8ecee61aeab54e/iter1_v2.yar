rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting conditional checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 4C 24 30 00 8D 4C 24 30 EA EC DD 30 EA }
        $pattern1 = { 8D 4C 24 60 00 8D 4C 24 60 EA EC DD 60 EA }
        $pattern2 = { E8 AB 00 00 00 00 E8 AB 00 00 00 CA EA }

    condition:
        any of them
}