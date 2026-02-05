rule bypass_evasion
{
    meta:
        description = "Evasion bypass patterns targeting memory address checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 00 FF C8 FF FF FF FF 40 E7 FF }
        $pattern1 = { 6A ?? 5A ?? 8B EC E8 03 F0 9E 85 C0 5A ?? FF 75 08 5D ?? }
        $pattern2 = { 64 A1 30 00 00 00 00 8B 41 E8 00 C8 FF FF FF FF 5A ?? FF 75 08 5D ?? }
    condition:
        (any of $pattern0, $pattern1, or $pattern2 match)
}