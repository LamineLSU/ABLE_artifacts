rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 6F 74 00 00 84 C0 74 20 }
        $pattern1 = { FF 75 08 FF 15 5C 00 6E 00 50 FF 15 04 01 6E 00 }
        $pattern2 = { 8B CE E8 0B 00 00 00 59 FF 75 08 E8 0B 00 00 00 }

    condition:
        any of them
}