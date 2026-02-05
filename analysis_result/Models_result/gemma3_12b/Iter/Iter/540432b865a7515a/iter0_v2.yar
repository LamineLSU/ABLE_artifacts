rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 0B 00 00 00 59 FF 75 08 FF 15 8C E1 C0 00 }
        $pattern1 = { 8B FF 55 8B EC E8 C8 FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }
        $pattern2 = { 8B FF 55 8B EC E8 07 26 00 00 83 F8 01 74 20 FF 75 08 FF 15 3C E1 C0 00 }

    condition:
        any of them
}