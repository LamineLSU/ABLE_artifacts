rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 FD FF FF 8D 95 F0 FE FF FF }
        $pattern1 = { 50 FF 15 88 A0 0E 01 01 0E 61 F7 53 }
        $pattern2 = { 50 FF 15 88 A0 36 00 00 36 61 F7 53 }

    condition:
        any of them
}