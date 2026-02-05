rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 ?? ?? ?? ?? E8 B9 61 02 00 8B 35 ?? }
        $pattern2 = { 75 66 ?? ?? ?? ?? 74 1F ?? ?? 8B 45 ?? }

    condition:
        any of them
}