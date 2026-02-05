rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 C0 74 27 01 FF 15 F4 63 45 00 85 C0 74 16 }
        $pattern1 = { 68 C0 74 27 01 FF 15 F8 63 45 00 85 C0 74 16 }
        $pattern2 = { FF D0 FF 14 28 C6 42 50 85 C0 74 16 }

    condition:
        any of them
}