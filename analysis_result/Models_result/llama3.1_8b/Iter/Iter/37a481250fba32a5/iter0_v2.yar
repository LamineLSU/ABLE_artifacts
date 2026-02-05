rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 40 53 33 C9 E8 4B 17 ?? ?? ?? ?? A1 88 85 ?? }
        $pattern1 = { 53 FF 15 AC B0 ?? FF E8 C8 FF ?? ?? ?? ?? }
        $pattern2 = { 55 FF 75 08 E8 C8 FF ?? ?? ?? ?? }

    condition:
        any of them
}