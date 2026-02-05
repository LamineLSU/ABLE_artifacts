rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 1C 27 47 00 FF 15 F4 63 45 00 85 C0 74 16 68 0C 27 47 00 50 FF 15 F8 63 45 00 }
        $pattern1 = { FF 74 24 04 FF D0 FF 74 24 04 FF 15 8C 62 45 00 }
        $pattern2 = { 68 0C 27 47 00 50 FF 15 F8 63 45 00 85 C0 74 16 }

    condition:
        any of them
}