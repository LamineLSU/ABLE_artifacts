rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 6A 40 53 68 40 11 2F 00 33 C9 E8 4B 17 00 00 A1 88 85 2F 00 FF 15 2C A1 2F 00 }
        $pattern1 = { 53 6A 40 53 68 40 11 88 00 33 C9 E8 4B 17 00 00 A1 88 85 88 00 FF 15 2C A1 88 00 }
        $pattern2 = { 55 8B EC FF 75 08 50 FF 15 AC B0 41 00 }

    condition:
        any of them
}