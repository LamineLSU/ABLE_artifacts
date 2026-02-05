rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting suspicious points"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 }
        $pattern1 = { FF7508 8B EC 85C0 ???? 83C4 ?? 85C0 }
        $pattern2 = { E8 ?? 7407 8B 45 ?? }

    condition:
        any of them
}