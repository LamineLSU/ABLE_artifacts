rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6B CD 38 70 CA 55 8B EC 8B 45 ?? }
        $pattern2 = { 70 CA 55 8B EC 8B 45 ?? 8B 88 ?? ?? ?? }

    condition:
        any of them
}