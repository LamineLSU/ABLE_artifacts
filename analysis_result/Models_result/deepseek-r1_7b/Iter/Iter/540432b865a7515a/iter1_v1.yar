rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Chain of conditional jumps and calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern1 = { 74 07 8D 8D E8 ?? ?? ?? ?? 8B 34 }
        $pattern2 = { 0F 84 0F 85 E8 ?? ?? ?? ?? FF ?? }

    condition:
        any of them
}