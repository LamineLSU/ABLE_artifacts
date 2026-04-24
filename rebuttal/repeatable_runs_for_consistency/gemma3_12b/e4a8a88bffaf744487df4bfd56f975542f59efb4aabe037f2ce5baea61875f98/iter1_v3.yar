rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 E3 D2 FF FF 8D 85 4C F2 FF FF }
        $pattern1 = { 50 A1 AC 5B 89 02 E8 E7 E9 FF FF 8B D0 }
        $pattern2 = { 8D 85 40 F2 FF FF E8 72 E5 FF FF 8B 85 40 F2 FF FF }

    condition:
        any of them
}