rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting memory manipulation"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 00 00 00 8A 40 ?? 00 00 00 }
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F ?? ?? ??}
        $pattern2 = { FF ?? ?F 88 7C 0D FF ?? ?F 88 7E }

    condition:
        any of them
}