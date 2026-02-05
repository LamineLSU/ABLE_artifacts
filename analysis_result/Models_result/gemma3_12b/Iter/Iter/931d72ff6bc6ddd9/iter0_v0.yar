rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 55 8B EC FF 75 08 E8 C8 FF FF FF 59 }
        $pattern1 = { 6A 40 53 68 40 11 1E 00 33 C9 E8 4B 17 00 00 }
        $pattern2 = { 55 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}