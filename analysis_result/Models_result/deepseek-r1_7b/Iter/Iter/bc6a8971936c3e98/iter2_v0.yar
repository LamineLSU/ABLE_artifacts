rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F5 E8 75 C3 7D 61 00 }
        $pattern1 = { E8 BE 55 E7 5F 8C 08 D0 00 }
        $pattern2 = { 6A 7D 5B 4C 59 F3 0E 40 00 }

    condition:
        any of them
}