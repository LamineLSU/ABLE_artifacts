rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rules targeting exitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C8 ?? ?? ?? ?? 8B 44 ?? }
        $pattern1 = { 74 07 ?? ?? ?? ?? 85 C0 ?? }
        $pattern2 = { E8 0D 0C 00 00 ?? ?? ?? ?? ?? }

    condition:
        any of them
}