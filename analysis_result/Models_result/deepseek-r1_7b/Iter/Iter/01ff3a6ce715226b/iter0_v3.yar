rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules for exit process"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 CE 85 C0 ?? ?? ?? ?? ?? 8B 55 EC CE }
        $pattern1 = { EC 6A 5A 37 ?F 55 ?D E8 ?E FC E2 FE 5A ?? ?? }
        $pattern2 = { CE CA 5A 37 ?B 45 ?C E8 ?? ?? ?? ?? 8B 45 8B }
}

condition:
    (any of the patterns match)