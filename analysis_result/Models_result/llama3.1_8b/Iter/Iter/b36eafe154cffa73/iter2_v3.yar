rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 3D ?? ?? ?? ?? 0F 82 }
        $pattern1 = { 8B 45 FC 83 F8 ?? 74 ?? 8B 4D F8 }
        $pattern2 = { 0F A6 C0 1E 00 48 89 EC }

    condition:
        any of them
}