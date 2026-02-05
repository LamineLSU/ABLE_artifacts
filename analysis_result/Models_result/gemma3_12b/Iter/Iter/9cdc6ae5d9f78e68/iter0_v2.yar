rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 4E 00 00 00 FF 15 A8 30 2E 01 }
        $pattern1 = { FF 15 A8 30 2E 01 8B FF 55 8B EC }
        $pattern2 = { E8 B7 B2 00 00 83 F8 01 74 20 64 A1 30 00 00 00 }

    condition:
        any of them
}