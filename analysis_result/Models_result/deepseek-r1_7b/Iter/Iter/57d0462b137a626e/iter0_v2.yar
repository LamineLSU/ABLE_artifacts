rule Bypass_Sample
{
    meta:
        description = "Evasion bypass by skipping jump instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 5B 8C 7D ?? ?? ?? ?? ?? }
        $pattern1 = { 8B EC 5A 40 ?? FF 75 08 E8 ?? C8 F4 30 12 E8 ?? ?? ?? E8 25 05 00 E8 ?? }
        $pattern2 = { 6A 40 8C 7D ?? E8 07 26 00 ?? 8B 4D FC 5A ?? FF 75 08 E8 ?? ?? }

    condition:
        any of them
}