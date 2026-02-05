rule Bypass_Sample_Evasion
{
    meta:
        description = "Evasion bypass targeting various exit points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 ?? 5A 8B CE E8 ?? 33 DB 5F 00 00 00 1F 0F FF FF FF 6E 1D 9C F2 00 00 }
        $pattern1 = { 6A ?? 5B 8B CE E8 ?? 74 03 03 DD 00 00 00 2F ?? ?? ?? ?? FF 15 2D 68 FE FF FF FF 8D 8D }
        $pattern2 = { 0F 84 74 0C 00 ?? ?? 33 C9 5B 00 00 01 0F 84 74 FC 5B FF FF FF FF E8 6A 5D 21 }
    condition:
        any of them
}