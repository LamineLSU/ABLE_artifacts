rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { E8 } { 4 } { 84 } { 66 } { 74 } { 2 }
        $pattern1 = { 50 } { FF15 } { 4 }
        $pattern2 = { FF 75 } { FF15 } { 4 }

    condition:
        all of them
}