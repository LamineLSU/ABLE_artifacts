rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 50 A1 ?? ?? ?? ?? 8B 00 FF D0 6A 00 E8 ?? ?? ?? ?? }
        $pattern1 = { 89 85 EC FE FF F8 E8 ?? ?? ?? ?? }
        $pattern2 = { 8B 45 08 E8 ?? ?? ?? ?? }

    condition:
        any of them
}