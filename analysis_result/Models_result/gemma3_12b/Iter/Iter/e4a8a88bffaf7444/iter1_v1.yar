rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 E3 D2 FF FF 8D 85 4C F2 FF FF E8 72 E5 FF FF }
        $pattern1 = { 8D 85 48 F2 FF FF E8 72 E5 FF FF 8B 85 48 F2 FF FF 5A E8 E3 D2 FF FF }
        $pattern2 = { 8D 85 44 F2 FF FF BA D8 F6 88 02 E8 72 E5 FF FF 8B 85 44 F2 FF FF 50 A1 AC 5B 89 02 }

    condition:
        any of them
}