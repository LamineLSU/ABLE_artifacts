rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved using known bypass techniques"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? }
        $pattern1 = { 6A ?? 5A ?? ?? }
        $pattern2 = { 0F 84 ?? ?? ?? }

    condition:
        any of them
}