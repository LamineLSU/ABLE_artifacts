rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting call instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $pattern1 = { FC 05 00 00 ?? ?? ?? ?? 8B 45 ?? ?? ?? }
        $pattern2 = { 7E FF 01 00 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? }

    condition:
        any of them
}