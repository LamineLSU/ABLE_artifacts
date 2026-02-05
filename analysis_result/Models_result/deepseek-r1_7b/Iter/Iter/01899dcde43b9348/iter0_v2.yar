rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting exit calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 45 C0 }
        $pattern1 = { E8 ?? ?? ?? ?? CA CB }
        $pattern2 = { 0F C7 ?? ?? ?? ?? }

    condition:
        any of them
}