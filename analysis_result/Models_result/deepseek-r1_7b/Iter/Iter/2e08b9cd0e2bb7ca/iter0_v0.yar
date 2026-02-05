rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 45 FF ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { F7 CA ?? ?? ?? ?? 5E 4F ?? ?? ?? ?? 6A ??.?? }
        $pattern2 = { 8B 45 C0 0F 84 ?? ?? ?? ?? E8 C0 ?? }

    condition:
        any of them
}