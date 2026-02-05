rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting potential security mechanisms"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E9 45 F0 FE FF FF }
        $pattern1 = { 74 07 BA 04 00 00 01 00 FF 15 2C A1 19 00 }
        $pattern2 = { 6A 5B 5A 8B CE E8 25 00 00 00 50 00 00 00 00 00 85 C0 }

    condition:
        (any_of($pattern0, $pattern1, $pattern2))
}