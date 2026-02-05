rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved specific calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 5B B6 E8 C2 ?? ?? }
        $pattern1 = { 3D 7E 49 ?? 58 ?? }
        $pattern2 = { 5C 33 DD 8A ?? ?? }

    condition:
        any of them
}