rule Bypass_Sample
{
    meta:
        description = "Three bypass rules targeting evasive points in code"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 90 00 00 00 5D ?? ?? C2 08 00 }
        $pattern1 = { 83 BD 04 F9 FF FF 01 ?? ?? ?? FF C9 C2 08 00 }
        $pattern2 = { E8 1D 03 00 00 5A 6A ?? 50 E8 B2 45 C7 06 00 00 00 ?? }

    condition:
        any of them
}