rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 17 10 3A FF 15 BC 36 38 00 }
        $pattern1 = { 00 17 10 BA FF 15 BC 36 38 00 }
        $pattern2 = { 00 17 D0 AC FF 15 BC 36 38 00 }

    condition:
        any of them
}