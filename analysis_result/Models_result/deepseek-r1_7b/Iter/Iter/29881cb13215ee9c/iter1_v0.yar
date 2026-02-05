rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific address/offset usage"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 D9 ?? 5A ?? }
        $pattern1 = { 6A ?F 5E 8B CE ?F ?? ?D 85 C0 }
        $pattern2 = { E8 B0 F3 FB 8C ?F FF ?? ?F 74 0F 84 }

    condition:
        any of them
}