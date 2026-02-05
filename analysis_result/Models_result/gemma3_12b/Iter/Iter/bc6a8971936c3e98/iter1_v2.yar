rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 51 53 56 57 33 FF 57 6A 40 BE 00 30 00 00 56 68 D0 07 00 00 57 FF 15 94 37 61 00 }
        $pattern1 = { 55 8B EC 83 E4 F8 83 EC 40 6A 40 33 C0 59 C6 04 04 00 85 C0 75 00 40 3B C1 }
        $pattern2 = { E8 44 C1 00 00 8B 15 54 34 61 00 E8 D8 F9 FF FF 85 C0 75 1B 50 }

    condition:
        any of them
}