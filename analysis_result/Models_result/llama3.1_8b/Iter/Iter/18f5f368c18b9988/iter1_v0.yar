rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 6A 04 ?? ?? ?? ?? 68 00 30 00 00 BE 70 5D 1E 00 }
        $pattern1 = { E8 A5 29 02 00 83 C4 0C 53 57 }
        $pattern2 = { FF 15 88 00 26 00 8B F8 50 }

    condition:
        any of them
}