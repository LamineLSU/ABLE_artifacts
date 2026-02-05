rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass using conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 75 8A ?? }
        $pattern1 = { 74 0F 84 ?? }
        $pattern2 = { 85 C0 ?? }

    condition:
        any of them
}