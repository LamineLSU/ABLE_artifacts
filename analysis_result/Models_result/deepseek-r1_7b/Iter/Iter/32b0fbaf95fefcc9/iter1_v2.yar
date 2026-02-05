rule Bypass_Evasion
{
    meta:
        description = "Bypasses evasion by manipulating stack and conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? 75 0C }
        $pattern1 = { F3 FF 00 8B 45 FC 6A ?? ?? 83 C4 ?? E8 ?? ?? 85 C0 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? 7E 9F 1D 8B CC }

    condition:
        any of them
}