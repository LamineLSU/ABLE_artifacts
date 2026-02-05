rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 74 24 04 E8 D1 FF FF FF 59 FF 74 24 04 FF 15 5C E0 40 00 }
        $pattern1 = { 8B FF 55 8B EC E8 F7 25 00 00 83 F8 01 74 20 }
        $pattern2 = { FF 75 08 FF 15 58 01 B8 00 50 FF 15 5C 01 B8 00 }

    condition:
        any of them
}