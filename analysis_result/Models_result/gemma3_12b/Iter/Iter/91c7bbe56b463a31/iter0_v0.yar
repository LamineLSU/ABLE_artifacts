rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 00 F3 40 00 53 53 53 68 00 F3 40 00 53 53 53 }
        $pattern1 = { 68 FF 0F 1F 00 53 53 53 68 00 00 80 }
        $pattern2 = { 68 00 93 42 00 FF D6 68 00 93 42 00 FF D6 68 E4 92 42 00 FF D6 }

    condition:
        any of them
}