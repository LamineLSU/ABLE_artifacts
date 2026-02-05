rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 2C A0 41 00 8D 85 9C FD FF FF BA 03 00 00 00 E8 55 C3 FE FF }
        $pattern1 = { 55 8B 85 E8 FE FF FF A1 50 B1 41 00 8B 00 FF D0 6A 00 }
        $pattern2 = { 8B 00 FF D0 6A 00 8B 85 84 FD FF FF 8D 85 80 FD FF FF }

    condition:
        any of them
}