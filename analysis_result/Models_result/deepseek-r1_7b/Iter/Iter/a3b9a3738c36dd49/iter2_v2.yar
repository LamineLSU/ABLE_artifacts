rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule using specific call sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 4B ?? ?? ?? 85 C0 ?F 75 09 }
        $pattern1 = { E8 F3 ?? ?? ?? FF 0E 0A 0F 84 85 }
        $pattern2 = { 6A 5A 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 }

    condition:
        any of them
}