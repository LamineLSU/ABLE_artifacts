rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection using multiple target patterns"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 FF FF FF 59 FF 75 08 E8 C8 FF FF }
        $pattern1 = { FF 75 08 E8 C8 FF FF FF 59 FF 75 08 E8 B0 AC }
        $pattern2 = { E8 C8 FF FF 59 FF 75 08 E8 C8 FF FC 59 FF 75 08 E8 B0 AC }
    condition:
        any_of_them
}