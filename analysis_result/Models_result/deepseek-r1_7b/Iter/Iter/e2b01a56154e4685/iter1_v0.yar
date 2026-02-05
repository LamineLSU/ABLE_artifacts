rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass using specific API calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { E9 B5 FC FF FF ?? ?? ?? ?? ?? 3D }
        $pattern2 = { 00 38 61 F8 74 12 8B 4F C0 00 E8 0D 0C 00 00 CC }

    condition:
        any of them
}