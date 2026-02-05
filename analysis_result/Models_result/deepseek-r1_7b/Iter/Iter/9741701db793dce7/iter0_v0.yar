rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { E8 E0 A2 FF FF 85 C0 74 0E ?? }
        $pattern2 = { B7 F7 F7 FF FF 6A ?? }

    condition:
        any of them
}