rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 9D 21 00 00 }
        $pattern1 = { 83 F8 01 74 20 64 A1 30 00 00 00 }
        $pattern2 = { 50 FF 15 BC F0 40 00 E8 4F 00 00 00 }

    condition:
        any of them
}