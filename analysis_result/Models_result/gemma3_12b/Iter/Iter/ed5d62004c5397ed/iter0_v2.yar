rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 6A 40 53 68 40 11 E2 00 33 C9 E8 4B 17 00 00 A1 88 85 E2 00 }
        $pattern1 = { 53 6A 40 53 68 40 11 3E 00 33 C9 E8 4B 17 00 00 A1 88 85 3E 00 }
        $pattern2 = { 50 55 8B EC E8 07 26 00 00 83 F8 01 74 20 FF 75 08 FF 15 8C E1 2C 00 }

    condition:
        any of them
}