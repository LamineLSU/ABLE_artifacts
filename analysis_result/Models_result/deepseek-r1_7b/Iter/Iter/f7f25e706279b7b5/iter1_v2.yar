rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - refined"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 55 14 8B 45 10 }
        $pattern1 = { 8B 55 14 8B 45 10 8B 4D 0C 83 C4 14 }
        $pattern2 = { 8B 55 14 8B 45 10 8B 4D 0C 83 C4 14 0F 84 85 C0 }
    condition:
        any of them
}