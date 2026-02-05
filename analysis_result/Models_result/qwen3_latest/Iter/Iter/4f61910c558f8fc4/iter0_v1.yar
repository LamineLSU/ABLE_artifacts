rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 4D FC E8 ?? ?? ?? ?? }
        $pattern1 = { 85 C0 0F 84 ?? ?? ?? ?? }
        $pattern2 = { BA 04 01 00 00 03 C1 E8 ?? ?? ?? ?? }

    condition:
        any of them
}