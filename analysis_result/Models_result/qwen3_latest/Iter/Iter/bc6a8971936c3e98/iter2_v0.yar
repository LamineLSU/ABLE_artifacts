rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 85 C0 75 07 FF 15 ?? ?? ?? ?? }
        $pattern1 = { 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $pattern2 = { 55 FF 15 ?? ?? ?? ?? }

    condition:
        all of them
}