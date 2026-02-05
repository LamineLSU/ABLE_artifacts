rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 85 9C FD FF FF BA 03 00 00 00 E8 55 C3 FE FF 8B 85 9C FD FF FF E8 D9 CE FF FF 89 85 E8 FE FF FF }
        $pattern1 = { 8B 85 9C FD FF FF BA 03 00 00 00 E8 55 C3 FE FF 8B 85 9C FD FF FF E8 D9 CE FF FF 5A 59 59 }
        $pattern2 = { 8B 95 80 FD FF FF 8D 85 84 FD FF FF E8 AD C2 FE FF 8B 85 84 FD FF FF 8D 95 88 FD FF FF E8 28 E2 FE FF }

    condition:
        any of them
}