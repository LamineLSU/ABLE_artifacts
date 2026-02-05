rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 9C FD FF FF 8B 85 9C FD FF FF E8 D9 CE FF FF }
        $pattern1 = { 8B 85 9C FD FF FF E8 D9 CE FF FF 89 85 E8 FE FF FF }
        $pattern2 = { E8 D9 CE FF FF 89 85 EC FE FF FF 33 C0 }

    condition:
        any of them
}