rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - specific calls to bypass execution"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 3D 00 10 00 00 0F 82 }
        $pattern2 = { E8 4E 2A 00 01 06 01 7C }

    condition:
        any of them
}