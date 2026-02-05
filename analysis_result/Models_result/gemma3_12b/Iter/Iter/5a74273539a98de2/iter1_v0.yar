rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 64 A1 30 00 00 00 8B 40 68 8B 45 ?? }
        $pattern1 = { FF 15 3C E1 BA 00 50 FF 15 40 E1 BA 00 E8 0B 00 00 00 }
        $pattern2 = { 8B FF 55 8B EC E8 07 26 00 00 83 F8 01 74 20 }

    condition:
        any of them
}