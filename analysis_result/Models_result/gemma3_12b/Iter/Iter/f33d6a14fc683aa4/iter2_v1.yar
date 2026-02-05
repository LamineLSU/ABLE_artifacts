rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 85 F0 FE FF FF 8D 8D F8 FE FF FF }
        $pattern2 = { 6A 40 53 68 40 11 A3 00 33 C9 E8 4B 17 00 00 A1 88 85 A3 00 }

    condition:
        any of them
}