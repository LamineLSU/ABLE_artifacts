rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip"

    strings:
        $pattern0 = { 6A 03 FF 15 ?? ?? ?? ?? 6A 02 EB F6 }
        $pattern1 = { 85 FF 74 ?? 8B 45 ?? }
        $pattern2 = { FF 15 ?? ?? ?? ?? 6A 03 }

    condition:
        all of them
}