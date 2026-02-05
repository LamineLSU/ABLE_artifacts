rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 FC }
        $pattern1 = { 68 C0 9E E6 05 53 57 E8 82 3D 01 00 }
        $pattern2 = { 83 F8 11 74 05 8B 4D F8 }

    condition:
        any of them
}