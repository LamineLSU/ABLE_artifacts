rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 20 }
        $pattern1 = { 20 FF EE CE }
        $pattern2 = { 20 FF EE CE }

    condition:
        any of them
}