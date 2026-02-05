rule Bypass_Sample
{
    meta:
        description = "Evasion bypass detection through instruction skipping"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 FF ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { 6A ?? EB 8B EC E8 ?? ?? ?? ?? FF 75 08 ?? }
        $pattern2 = { ?? ?? ?? ?? ?? ?? 75 10 01 0C A9 D0 ?? }
    condition:
        any of them
}