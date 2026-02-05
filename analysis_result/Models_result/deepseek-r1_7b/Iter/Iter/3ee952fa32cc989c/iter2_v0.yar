rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting call evasions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF E7 F3 FF 75 08 E8 C8 FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }
        $pattern1 = { FF 75 08 FF 15 AC B0 41 00 6A 5A 8B EC E8 ?? ?? ?? ?? 83 C4 85 C0 0F 84 }
        $pattern2 = { FF 75 08 FF 15 AC B0 41 00 8B FF 55 8B EC E8 C8 FF FF FF 59 FF 75 08 FF 15 AC B0 41 00 }

    condition:
        any of them
}