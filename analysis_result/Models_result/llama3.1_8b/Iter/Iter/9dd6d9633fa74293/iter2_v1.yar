rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern2+0,action0=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 3D 00 10 00 00 0F 82 }
        $pattern2 = { 83 F8 ?? 74 12 8B 4D F8 }

    condition:
        any of them
}