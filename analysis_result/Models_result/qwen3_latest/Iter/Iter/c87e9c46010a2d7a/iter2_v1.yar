rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 8B 4D ?? 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern1 = { 53 FF 15 ?? ?? ?? ?? }
        $pattern2 = { 8B 4D ?? 85 C0 74 ?? }

    condition:
        all of them
}