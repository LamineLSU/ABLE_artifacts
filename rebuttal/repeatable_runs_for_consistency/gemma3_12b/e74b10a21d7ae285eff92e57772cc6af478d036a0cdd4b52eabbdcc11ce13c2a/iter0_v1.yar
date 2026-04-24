rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF 03 C3 BA 04 01 00 00 03 C1 B9 42 8C 07 01 }
        $pattern2 = { FF 15 2C A1 0B 00 53 6A 40 53 68 40 11 B9 00 33 C9 E8 B3 03 00 00 A1 88 85 B9 00 }

    condition:
        any of them
}