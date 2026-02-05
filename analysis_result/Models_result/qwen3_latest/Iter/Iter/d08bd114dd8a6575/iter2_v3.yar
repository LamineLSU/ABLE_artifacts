rule EvolvedBypassRule
{
    meta:
        description = "Evolved bypass rule for sample d08bd114dd8a6575"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 88 18 0A 00 00 }
        $pattern1 = { 50 E8 74 0A 00 00 }
        $pattern2 = { 52 FF D0 5E 5D C3 }

    condition:
        any of them
}