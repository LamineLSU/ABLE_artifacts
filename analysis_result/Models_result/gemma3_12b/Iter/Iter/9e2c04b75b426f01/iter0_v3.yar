rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC FF 75 08 FF 15 8C E1 14 00 } // 13A9DC: FF158CE11400
        $pattern1 = { 8B FF 55 8B EC E8 C8 FF FF FF 59 FF 75 08 } // 40E7F6: E8C8FFFFFF
        $pattern2 = { 64 A1 30 00 00 00 8B 40 68 8B ?? ?? ?? ?? } // 13A9B0: 64A130000000

    condition:
        any of them
}