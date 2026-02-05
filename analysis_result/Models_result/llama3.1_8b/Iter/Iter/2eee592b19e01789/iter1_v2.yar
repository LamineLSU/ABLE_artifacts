rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { FF 15 A9 16 01 00 CA LL QW OR D PT R [0 00 07 FF 77 8B 2A 12 8H ] }
        $pattern2 = { FF 15 1E 17 01 00 CA LL QW OR D PT R [0 00 07 FF 77 8B 2A 0A 8H ] }

    condition:
        any of them
}