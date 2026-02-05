rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ?? ?? ?? }
        $pattern1 = { 3D ?? ?? ?? ?? 0F 82 ?? ?? ?? ?? }
        $pattern2 = { C1 E8 08 A8 01 75 10 FF 15 ?? ?? }

    condition:
        any of them
}