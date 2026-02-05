rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 64 48 D1 00 FF 15 20 41 D1 00 }
        $pattern1 = { 68 70 48 D1 00 50 FF 15 1C 42 D1 00 85 C0 }
        $pattern2 = { 68 10 20 00 00 FF D0 68 A4 48 D1 00 68 B0 48 D1 00 6A 00 FF D0 }

    condition:
        any of them
}