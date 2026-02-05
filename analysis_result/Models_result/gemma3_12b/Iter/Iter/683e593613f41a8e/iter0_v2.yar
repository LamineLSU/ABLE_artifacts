rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 00 40 E7 EE 8B FF 55 8B EC 5D } // 0040E7FF call
        $pattern1 = { 00 07 A9 A1 8B FF 55 8B EC E8 07 26 00 00 } // 0007A9DC call
        $pattern2 = { 00 40 E7 EE 8B FF 55 8B EC E8 07 26 00 00 } // 0040E7F6 call

    condition:
        any of them
}