rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 9C FD FF FF BA 03 00 00 00 E8 55 C3 FE FF 8B 85 9C FD FF FF E8 D9 CE FF FF }
        $pattern1 = { 6A 00 BA 03 00 00 00 33 C0 E8 E4 B7 FE FF 5A }
        $pattern2 = { 8D 95 80 FD FF FF 33 C0 E8 A5 91 FE FF 8B 95 80 FD FF FF }

    condition:
        any of them
}