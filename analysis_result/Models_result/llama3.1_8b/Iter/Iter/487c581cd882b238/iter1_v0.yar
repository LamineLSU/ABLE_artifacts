rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 6A 5B 5A 8D 95 F0 FE FF FF 89 D9 }
        $pattern2 = { 3D 00 10 00 00 0F 82 }

    condition:
        any of them
}