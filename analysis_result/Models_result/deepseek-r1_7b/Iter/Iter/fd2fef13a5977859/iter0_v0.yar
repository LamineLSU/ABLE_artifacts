rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass detection rules"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B FF 55 8B EC E8 ?? ?? ?? }
        $pattern1 = { 74 20 FF ?? 02 00 ?? ?? }
        $pattern2 = { FF 1A FF ?? FF 3C FF 40 FF C0 }

    condition:
        any of them
}