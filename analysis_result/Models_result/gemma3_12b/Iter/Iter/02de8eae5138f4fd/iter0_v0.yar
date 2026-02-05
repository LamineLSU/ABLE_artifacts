rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 00 E8 A5 10 00 00 A3 C9 40 40 00 }
        $pattern1 = { E8 57 03 00 00 E9 45 FD FF FF 6A 02 FF B5 A4 FC FF FF }
        $pattern2 = { 6A 00 E8 87 07 00 00 8B 85 64 F9 FF FF }

    condition:
        any of them
}