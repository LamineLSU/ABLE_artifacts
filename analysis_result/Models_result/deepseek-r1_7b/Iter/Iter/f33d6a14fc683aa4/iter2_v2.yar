rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific CALL/JMP sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B C0 FF ?? ?? ?? ?? 74 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? 5F ?? ?F 73 ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 75 ?? }

    condition:
        any of them
}