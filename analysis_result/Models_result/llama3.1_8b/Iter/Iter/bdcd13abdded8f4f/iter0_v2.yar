rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B EC 00 51 E8 ?? ?? ?? ?? 8B 45 }
        $pattern1 = { 59 E8 ?? ?? ?? ?? 52 92 }
        $pattern2 = { 5E E8 ?? ?? ?? ?? FF D0 C3 }

    condition:
        any of them
}