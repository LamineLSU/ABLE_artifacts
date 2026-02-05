rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific instruction sequence targeting"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 59 FF 75 08 E8 C8 FF FF FF }
        $pattern1 = { 00 40 E7 F6 00 40 E7 FF 8B EC FF 75 08 00 40 E7 FC 59 E8 C8 FF FF FF }
        $pattern2 = { 8B 45 FC 00 40 E7 F3 FF 75 08 00 40 E7 FB 59 E8 C8 FF FF FF }

    condition:
        any of them
}