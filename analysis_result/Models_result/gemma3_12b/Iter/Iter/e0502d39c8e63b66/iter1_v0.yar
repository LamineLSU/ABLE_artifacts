rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 EC 48 56 FF 15 BC A0 41 00 83 65 E4 00 }
        $pattern1 = { 59 8D BD 9C FC FF FF F3 A5 6A 22 58 66 A5 A4 8D B5 A4 FE FF FF }
        $pattern2 = { 53 68 14 A9 41 00 FF 15 38 A2 41 00 68 20 A9 41 00 50 FF 15 2C A2 41 00 }

    condition:
        any of them
}