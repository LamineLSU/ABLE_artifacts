rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection using specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,count=0"

    strings:
        $pattern0 = { FF 75 08 E8 C8 FF FF FF ?? }
        $pattern1 = { 55 8B EC FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 ?? }
        $pattern2 = { 59 FF 75 08 8B EC FF 75 08 E8 C8 FF FF FF FF 15 AC B0 41 00 ?? }

    condition:
        any of them
}