rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 75 07 FF 15 BC 36 38 00 85 C0 }
        $pattern1 = { 55 8B EC 51 53 56 57 33 FF 57 6A 40 BE 00 30 00 00 56 68 D0 07 00 00 57 FF 15 94 37 38 00 }
        $pattern2 = { 55 8B EC 83 E4 F8 83 EC 0C 6A 7C 58 68 E0 1E 18 00 FF 75 08 66 89 45 FC FF 15 54 37 38 00 }

    condition:
        any of them
}