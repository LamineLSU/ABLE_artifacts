rule Bypass_Evasion_Patterns
{
    meta:
        description = "Evasion bypass detection patterns targeting specific instructions"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8D 85 4F 2F FF ?? ?? ?? ?? BA D8 F6 88 12 }
        $pattern1 = { BA CC F6 88 02 E8 72 E5 FF FF ?? ?? ?? ?? }
        $pattern2 = { BA D8 F6 88 02 E8 72 E5 FF FF 8D 85 4F 2F FF }

    condition:
        any of them
}