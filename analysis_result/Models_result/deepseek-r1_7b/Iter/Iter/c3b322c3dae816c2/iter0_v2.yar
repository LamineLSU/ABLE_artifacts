rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection through address-dependent displacements in E8 calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 05 00 00 00 }
        $pattern1 = { E8 ?? ?? ?? ?? AC B0 41 ?? }
        $pattern2 = { E8 ?? ?? ?? ?? DC ?? ?? ?? ?? }

    condition:
        any of them
}