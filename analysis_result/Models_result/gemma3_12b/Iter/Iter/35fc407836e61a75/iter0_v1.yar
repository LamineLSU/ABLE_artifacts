rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 E8 C8 FF ?? FF 75 08 }
        $pattern1 = { 59 FF 15 AC B0 41 00 }
        $pattern2 = { 59 FF 15 8C E1 90 00 }

    condition:
        any of them
}