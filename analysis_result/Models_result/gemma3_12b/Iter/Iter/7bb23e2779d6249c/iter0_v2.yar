rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 10 5A 8B 45 08 E8 18 00 00 00 85 C0 }
        $pattern1 = { 8B 40 68 8B 48 0C C1 E8 08 A8 01 75 10 FF 75 08 }
        $pattern2 = { FF 75 08 E8 0B 00 00 00 59 FF 75 08 }

    condition:
        any of them
}