rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF } // 0040E7F6 call
        $pattern1 = { 8B FF 55 8B EC E8 07 26 00 00 83 F8 01 74 20 } // 003BA9A1 call
        $pattern2 = { 59 FF 75 08 FF 15 8C E1 3C 00 } // 003BA9D8 pop

    condition:
        any of them
}