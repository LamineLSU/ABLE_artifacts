rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass targeting specific exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip"

    strings:
        $pattern0 = { 00 40 E7 F3 FF 75 08 00 40 E7 F6 E8 C8 FF FF FF 00 40 E7 F7 59 00 40 E7 F8 FF 75 08 00 40 E7 F9 E8 C8 FF FF FF }
        $pattern1 = { 00 40 E7 FF FF 75 08 00 40 E7 FB E8 C8 FF FF FF 00 40 E7 FC 59 00 40 E7 FD FF 75 08 00 40 E7 FE E8 C8 FF FF FF }

    condition:
        (any of the patterns match)
}