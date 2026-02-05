rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 52 8B 16 50 51 FF D2 5E 5D C3 }
        $pattern1 = { E5 62 7B 74 F0 B6 61 57 C0 13 23 }
        $pattern2 = { 55 8B EC 8B 45 08 8B 48 14 56 50 E8 ?? ?? ?? ?? }

    condition:
        any of them
}