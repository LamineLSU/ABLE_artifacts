rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 53 6A 40 53 68 40 11 10 01 33 C9 E8 4B 17 00 00 A1 88 85 10 01 FF 15 AC B0 41 00 }
        $pattern1 = { 50 53 6A 40 53 68 40 11 03 01 33 C9 E8 E3 FA FF FF }
        $pattern2 = { 55 8B EC FF 75 08 E8 C8 FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}