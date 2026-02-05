rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC 83 C4 ?? }
        $pattern1 = { E8 0D 0C 00 00 CA 00 86 6E 2A 5A 8B CE 6A ?? 5A }
        $pattern2 = { FF 15 2C A1 86 00 CA DD 00 86 A1 2C 33 FF 8B C7 EB 03 }

    condition:
        any of them
}