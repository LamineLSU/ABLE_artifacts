rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC 83 EC 48 56 FF 15 BC A0 41 00 }
        $pattern1 = { 6A 22 58 66 A5 A4 8D B5 A4 FE FF FF }
        $pattern2 = { 68 00 00 00 08 53 53 53 8D 85 9C FC FF FF }

    condition:
        any of them
}