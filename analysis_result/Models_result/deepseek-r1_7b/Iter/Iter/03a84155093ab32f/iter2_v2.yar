rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting E8440900h"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 45 13 ?? 2A ??> ?? 6D 0F 84 45 ?? }
        $pattern1 = { E8 ?? 7C 0A 2B ??> ?? 6D 0F 84 45 ?? }
        $pattern2 = { E8 ?? ??> 7C 0A 2B ??> ?? 6D 0F 84 45 ?? }

    condition:
        any of them
}