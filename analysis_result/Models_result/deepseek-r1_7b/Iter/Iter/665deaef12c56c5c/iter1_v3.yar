rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specifically targeting known instruction sequences from exit process call"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 40 E7 F6 E8 C8 FF FF FF 41 B0 AC FF 15 AC B0 41 00 }
        $pattern1 = { 40 E7 F6 E8 C8 FF FF FF 40 E7 FB 59 40 E7 FC FF 75 08 }
        $pattern2 = { AC DA EC BE EE CA CE }

    condition:
        any of them
}