rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 ?? 53 56 57 33 C0 5F }
        $pattern1 = { C9 C3 57 FF 75 EC 53 }
        $pattern2 = { 0F 28 07 75 D1 8D 85 ?? ?? ?? ?? }

    condition:
        any of them
}