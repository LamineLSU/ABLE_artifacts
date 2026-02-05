rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8B CE E8 ?? ?? ?? ?? 59 }
        $pattern1 = { 68 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 59 } // Change from original suggestion
        $pattern2 = { 3D ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? }

    condition:
        any of them
}