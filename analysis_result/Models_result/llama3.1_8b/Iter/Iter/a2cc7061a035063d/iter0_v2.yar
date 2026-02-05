rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 C1 FF FF FF FF 75 08 FF 15 5C C2 4C 00 }
        $pattern1 = { 59 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { 8B EC E8 ?? ?? ?? ?? 59 85 C0 }

    condition:
        any of them
}