rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,count=0"

    strings:
        $pattern0 = { 8B EC ?? ?? ?? ?? 83 C4 ?? }
        $pattern1 = { E9 ?? ?? ?? ?? 8B 45 FC }
        $pattern2 = { 3D ?? ?? ?? ?? 74 ?? }

    condition:
        any of them
}