rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 F7 25 00 00 83 F8 01 74 20 }
        $pattern1 = { E8 D1 FF FF FF FF 74 24 04 59 FF 74 24 04 FF 15 5C E0 40 00 }
        $pattern2 = { 64 A1 30 00 00 00 8B 40 68 C1 E8 08 A8 01 75 10 }

    condition:
        any of them
}