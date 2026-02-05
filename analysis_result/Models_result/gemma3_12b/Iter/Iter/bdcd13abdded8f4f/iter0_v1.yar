rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF ?? ?? ?? ?? 5E 5D C3 }
        $pattern1 = { 7E BE ?? C3 55 8B EC 8B 45 ?? 8B 88 14 ?? ?? ?? ?? }
        $pattern2 = { 6A 36 6A 00 51 8D B0 7C ?? ?? ?? ?? 56 }

    condition:
        any of them
}