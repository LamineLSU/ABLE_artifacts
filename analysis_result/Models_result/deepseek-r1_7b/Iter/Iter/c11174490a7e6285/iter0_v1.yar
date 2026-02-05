rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns for sandbox detection"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 40 53 ?? 8B CE E8 74 0F 84 ?? ?? ?? ?? 74 12 }
        $pattern1 = { FF 15 88 A0 C2 A0 8B CE E8 B3 17 EA ?? ?? ?? ?? 74 07 }
        $pattern2 = { BA 21 05 00 00 6A 40 53 8B EC 0F 84 ?? ?? ?? ?? E8 74 }

    condition:
        any of them
}