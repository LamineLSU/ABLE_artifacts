rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 FF 75 ?? ?? 0A ?? 0B }
        $pattern1 = { FF 15 AC B0 41 00 00 6A 5B 53 ?? 80 ?? ?? }
        $pattern2 = { 00 00 01 01 00 00 80 0D 00 ?? ?? ?? }

    condition:
        any of them
}