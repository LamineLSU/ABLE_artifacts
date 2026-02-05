rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 33 CD E8 25 05 8B CE 90 FF FF 88 00 0D 53 FF 15 2C A1 0C 01 }
        $pattern1 = { 6A 5B 5A 8B CE E8 74 FA FF FF 03 C3 BA 04 01 00 00 8D 8D F8 FE FF FF 03 C1 B9 42 8C 09 01 50 FF 15 88 A0 0C 01 }
        $pattern2 = { FF 75 08 C1 E8 A8 01 75 10 FF 15 AC B0 41 00 59 FF 75 08 E8 0B 00 00 00 59 FF 75 08 }
    condition:
        any of them
}