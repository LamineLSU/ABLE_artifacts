rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? }
        $pattern1 = { 8D 41 01 80 FA 22 0F 45 C1 }
        $pattern2 = { 0F 45 C1 85 C0 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}