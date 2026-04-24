rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 6A 00 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 8B 45 ?? 8B 45 ?? }

    condition:
        all of them
}