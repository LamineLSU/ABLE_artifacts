rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 00 FF D0 6A 00 }
        $pattern1 = { 8B 85 94 FD FF FF BA 03 00 00 00 E8 F5 B9 FE FF }
        $pattern2 = { 8D 85 D4 FE FF FF 50 A1 64 B5 41 00 }

    condition:
        any of them
}