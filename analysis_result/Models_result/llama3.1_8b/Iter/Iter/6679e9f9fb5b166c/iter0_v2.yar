rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 D9 CE FF FF E8 A5 91 FE FF E8 E4 B7 FE FF }
        $pattern1 = { E8 D9 CE FF FF 33 C0 ?? ?? ?? ?? E8 E4 B7 FE FF }
        $pattern2 = { E8 A5 91 FE FF 33 C0 ?? ?? ?? ?? E8 E4 B7 FE FF }

    condition:
        any of them
}