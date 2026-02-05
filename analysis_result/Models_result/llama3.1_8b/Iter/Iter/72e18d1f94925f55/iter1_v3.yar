rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? 83 F8 01 74 ?? }
        $pattern1 = { C3 64 A1 ?? ?? ?? ?? 8B 40 68 C1 E8 ?? }
        $pattern2 = { 3D ?? ?? ?? ?? 0F 82 ?? ?? }

    condition:
        any of them
}