rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 FA 05 75 02 EB 02 }
        $pattern1 = { F7 F1 83 FA 05 75 02 }
        $pattern2 = { E8 ?? ?? ?? ?? B9 0A 00 00 00 }

    condition:
        any of them
}