rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 40 40 00 E8 90 F6 FF FF 8B D8 83 C4 04 85 DB 74 1B }
        $pattern1 = { 83 7C 24 18 00 74 0C 83 EC 10 53 E8 6B F3 FF FF 83 C4 04 }
        $pattern2 = { 55 8B EC 53 56 57 68 BC 18 AB 00 FF 74 24 10 FF 15 D8 90 AB 00 }

    condition:
        any of them
}