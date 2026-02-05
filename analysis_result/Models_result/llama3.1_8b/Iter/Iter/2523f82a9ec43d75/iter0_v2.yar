rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 53 ?? E8 E3 FA FF FF FF 15 2C A1 37 01 }
        $pattern1 = { 33 DB BA 21 05 00 00 53 6A 40 53 }
        $pattern2 = { 8B FF 55 8B EC FF 75 08 E8 C8 FF FF FF }

    condition:
        any of them
}